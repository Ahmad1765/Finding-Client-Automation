# ponytail: Zero dependencies. Using stdlib urllib, json, smtplib, sqlite3, random, time, and regex.
# 1. Finds leads via OpenStreetMap (Overpass API)
# 2. Checks SQLite ledger (leads.db) to ensure idempotency & deduplication
# 3. Scrapes homepage + 1-hop /contact fallback for email & text
# 4. Audits passive security headers & mobile viewport tag
# 5. Generates human, plain-text cold email via Groq API
# 6. Dispatches via SMTP with deliverability jitter (or logs dry-run draft)

import urllib.request
import urllib.parse
import json
import smtplib
import re
import os
import sys
import socket
import ipaddress
import ssl
import sqlite3
import random
import time
from email.message import EmailMessage

# ==========================================
# CONFIGURATION
# ==========================================
# ponytail: stdlib .env loader (avoids third-party dependencies)
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k_clean = k.strip()
                v_clean = v.strip().strip("'\"")
                os.environ.setdefault(k_clean, v_clean)
                os.environ.setdefault(k_clean.upper(), v_clean)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or os.environ.get("GROQ", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER") or os.environ.get("GMAILUSER", "")
SMTP_PASS = (os.environ.get("SMTP_PASS") or os.environ.get("GMAILSMTP", "")).replace(" ", "")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leads.db")

# ==========================================
# SQLITE PERSISTENCE & DEDUPLICATION
# ==========================================
def init_db():
    """Initializes the SQLite ledger for lead tracking and deduplication."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                city TEXT NOT NULL,
                website TEXT UNIQUE,
                phone TEXT,
                email TEXT,
                audit_findings TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                emailed_at TIMESTAMP
            )
        """)

def normalize_url(url):
    """Normalizes URL for canonical deduplication in SQLite."""
    if not url:
        return ""
    if "://" not in url:
        url = f"https://{url}"
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc.lower()}{p.path.rstrip('/')}"

def is_lead_processed(website):
    """Returns True if website domain/URL is already recorded in leads.db."""
    if not website:
        return False
    norm = normalize_url(website)
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT status FROM leads WHERE website = ?", (norm,)).fetchone()
        return row is not None

def record_lead(name, city, website, phone, email, audit_findings, status, emailed=False):
    """Inserts or updates a lead record in the SQLite ledger."""
    norm = normalize_url(website) if website else None
    findings_str = json.dumps(audit_findings) if isinstance(audit_findings, list) else (audit_findings or "")
    emailed_at = time.strftime('%Y-%m-%d %H:%M:%S') if emailed else None
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO leads (name, city, website, phone, email, audit_findings, status, emailed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(website) DO UPDATE SET
                phone = COALESCE(excluded.phone, leads.phone),
                email = COALESCE(excluded.email, leads.email),
                audit_findings = excluded.audit_findings,
                status = excluded.status,
                emailed_at = COALESCE(excluded.emailed_at, leads.emailed_at)
        """, (name, city, norm, phone, email, findings_str, status, emailed_at))

# ==========================================
# LEAD DISCOVERY (OPENSTREETMAP)
# ==========================================
def find_places_free(city, business_type):
    """Finds businesses using the free Overpass API (OpenStreetMap). No API key required!"""
    term = business_type.lower()
    tag = f'name~"{term}",i'
    if 'plumb' in term: tag = 'craft=plumber'
    elif 'electric' in term: tag = 'craft=electrician'
    elif 'restaurant' in term: tag = 'amenity=restaurant'
    elif 'cafe' in term: tag = 'amenity=cafe'
    elif 'dentist' in term: tag = 'amenity=dentist'
    elif 'roof' in term: tag = 'craft=roofer'

    query = f"""
    [out:json];
    area[name="{city}"]->.searchArea;
    nwr[{tag}](area.searchArea);
    out center;
    """
    
    url = "https://overpass-api.de/api/interpreter"
    data = urllib.parse.urlencode({'data': query}).encode('utf-8')
    req = urllib.request.Request(url, data=data)
    
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            res = json.loads(response.read().decode('utf-8'))
            places = []
            for el in res.get('elements', []):
                tags = el.get('tags', {})
                if not tags.get('name'): continue
                places.append({
                    'name': tags.get('name'),
                    'website': tags.get('website') or tags.get('contact:website'),
                    'phone': tags.get('phone') or tags.get('contact:phone')
                })
            return places
    except Exception as e:
        print(f"Error fetching free places: {e}")
        return []

# ==========================================
# SSRF PROTECTION & DNS PINNING
# ==========================================
_orig_getaddrinfo = socket.getaddrinfo
_dns_pin = {}

def _pinned_getaddrinfo(host, port, *args, **kwargs):
    key = host.lower() if isinstance(host, str) else host
    if key in _dns_pin:
        return _orig_getaddrinfo(_dns_pin[key], port, *args, **kwargs)
    return _orig_getaddrinfo(host, port, *args, **kwargs)

socket.getaddrinfo = _pinned_getaddrinfo

def is_safe_url(url):
    """Allows only HTTP(S) destinations resolving to public IP addresses and pins the validated IP."""
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ('http', 'https') or not p.hostname:
            return False
        hostname = p.hostname.lower()
        res = _orig_getaddrinfo(hostname, None)
        valid_ips = []
        for _, _, _, _, sockaddr in res:
            ip = ipaddress.ip_address(sockaddr[0])
            if not ip.is_global:
                return False
            valid_ips.append(sockaddr[0])
        if not valid_ips:
            return False
        _dns_pin[hostname] = valid_ips[0]
        return True
    except Exception:
        return False

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ensures HTTP redirects cannot escape to non-global or invalid destinations."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_url(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

# ponytail: ProxyHandler({}) disables env proxy so pinned IPs can't be bypassed via proxy settings
urllib.request.install_opener(urllib.request.build_opener(
    SafeRedirectHandler, urllib.request.ProxyHandler({})
))

# ==========================================
# SCRAPING, VIEWPORT AUDIT & 1-HOP FALLBACK
# ==========================================
def extract_emails(html):
    """Extracts unique emails preserving document order, skipping image asset extensions."""
    mailtos = re.findall(r'mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', html, re.I)
    raw_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html)
    return [e for e in dict.fromkeys(mailtos + raw_emails) if not e.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))]

def scrape_website(url):
    """Scrapes homepage and fallback /contact subpage for email, text content, and checks viewport."""
    if not is_safe_url(url):
        print(f"  [!] Skipped unsafe or invalid URL: {url}")
        return None, "", True
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            if response.headers.get_content_type() not in ('text/html', 'application/xhtml+xml', 'text/plain'):
                return None, "", True
            html = response.read(100000).decode('utf-8', errors='ignore')
            
            # Mobile responsiveness check: look for <meta name="viewport" ...>
            has_viewport = bool(re.search(r'<meta\b[^>]*?\bname=[\'"]viewport[\'"][^>]*>', html, re.I))

            emails = extract_emails(html)

            # 1-Hop /contact fallback if homepage lacks an email
            if not emails:
                candidates = re.findall(r'href=[\'"]([^\'"]*(?:contact|about)[^\'"]*)[\'"]', html, re.I)
                candidates.append('/contact')
                seen_candidates = set()
                parsed_root = urllib.parse.urlparse(url)

                for cand in candidates:
                    cand = cand.strip()
                    if not cand or cand.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                        continue
                    sub_url = urllib.parse.urljoin(url, cand)
                    if sub_url in seen_candidates:
                        continue
                    seen_candidates.add(sub_url)

                    # Restrict to same host and check SSRF safety
                    if urllib.parse.urlparse(sub_url).netloc.lower() != parsed_root.netloc.lower():
                        continue
                    if not is_safe_url(sub_url):
                        continue

                    try:
                        sub_req = urllib.request.Request(sub_url, headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(sub_req, timeout=5) as sub_res:
                            if sub_res.headers.get_content_type() in ('text/html', 'application/xhtml+xml', 'text/plain'):
                                sub_html = sub_res.read(100000).decode('utf-8', errors='ignore')
                                sub_emails = extract_emails(sub_html)
                                if sub_emails:
                                    emails = sub_emails
                                    print(f"  [+] Discovered email on contact page ({sub_url}): {emails[0]}")
                                    break
                    except Exception:
                        pass

            # Text extraction
            text_content = re.sub('<[^<]+?>', ' ', html)
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            
            target_email = emails[0] if emails else None
            return target_email, text_content[:2000], has_viewport
    except Exception as e:
        print(f"  [!] Could not scrape {url}: {e}")
        return None, "", True

# ==========================================
# PASSIVE SECURITY AUDIT
# ==========================================
def passive_security_scan(url):
    """Passively checks a website for missing security headers (Legal and safe)."""
    if not is_safe_url(url):
        return []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = response.headers
            missing = []
            csp = headers.get('Content-Security-Policy', '')
            if not csp:
                missing.append("CSP (Anti-XSS)")
            if 'Strict-Transport-Security' not in headers:
                missing.append("HSTS (HTTPS enforcement)")
            xfo = headers.get('X-Frame-Options', '').strip().upper()
            has_frame_ancestors = False
            for directive in csp.lower().split(';'):
                parts = directive.strip().split()
                if parts and parts[0] == 'frame-ancestors':
                    vals = parts[1:]
                    is_permissive = any(v == '*' or (v.endswith(':') and '//' not in v) for v in vals)
                    if vals and not is_permissive:
                        has_frame_ancestors = True
                    break
            has_framing_protection = has_frame_ancestors or (xfo in ('DENY', 'SAMEORIGIN'))
            if not has_framing_protection:
                missing.append("Anti-Clickjacking (X-Frame-Options / frame-ancestors)")
            return missing
    except Exception:
        return []

# ==========================================
# AI COPYWRITING (GROQ API)
# ==========================================
def generate_personalized_email(business_name, website_url, website_text, audit_issues):
    """Uses Groq API to write a personalized cold email based on website flaws, security risks, and mobile viewport."""
    issues_prompt = ""
    if audit_issues:
        issues_prompt = f"Key issues detected on their website: {', '.join(audit_issues)}."

    prompt = f"""
    Write a short, friendly, plain-text cold email to {business_name}.
    Their website is {website_url}. Based on their homepage text: "{website_text}", 
    they likely need a modern web redesign.
    {issues_prompt}
    Constraints:
    - Pitch a modern, responsive, and secure redesign addressing the issues observed.
    - Keep it strictly under 4 sentences.
    - Sound like a helpful neighbor/consultant, not a sales pitch. No corporate buzzwords (no "guarantee", "free trial", "act now").
    - Plain text only (no markdown, no links, no placeholders).
    """

    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = json.dumps({
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7
    }).encode('utf-8')
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {GROQ_API_KEY}',
        'User-Agent': 'Mozilla/5.0'
    }
    
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())
            return data['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f"Error calling Groq: {e}")
        return f"Hey {business_name}, I was looking at {website_url} and noticed a few ways it could be faster, more secure, and better optimized for mobile phones. Would love to share a quick suggestion if you're open to it!"

# ==========================================
# OUTREACH DISPATCH
# ==========================================
def send_email(to_email, subject, body):
    """Sends the email using SMTP."""
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"  [+] Email sent to {to_email}")
    except Exception as e:
        print(f"  [!] Failed to send email to {to_email}: {e}")

# ==========================================
# MAIN EXECUTION PIPELINE
# ==========================================
def main():
    init_db()
    send_live = "--send" in sys.argv

    print("--- 100% Free Lead Generation (Phase 2) ---")
    if send_live:
        print("  [!] LIVE SENDING MODE ENABLED (Jitter 45-90s active).")
    else:
        print("  [*] DRY-RUN MODE (Drafts saved to leads.db; pass --send to dispatch live).")

    city = input("Enter the city (e.g., 'Austin'): ").strip()
    business_type = input("Enter the business type (e.g., 'plumber', 'dentist'): ").strip()
    
    print(f"\nSearching for '{business_type}' in '{city}' using OpenStreetMap (Free)...\n")
    
    places = find_places_free(city, business_type)
    
    if not places:
        print("No places found. Try a larger city or a different business type.")
        return

    for place in places[:10]: # Limit to 10 for batch testing
        name = place.get('name')
        print(f"\n--- Processing: {name} ---")
        
        website = place.get('website')
        phone = place.get('phone', 'N/A')
        
        if not website:
            print(f"  [-] NO WEBSITE. (Phone: {phone})")
            print(f"  [-] Calling them is the best strategy. Logged to DB.")
            record_lead(name, city, None, phone, None, ["No website listed"], status='NO_WEBSITE')
            continue

        if "://" not in website:
            website = f"https://{website}"

        # SQLite deduplication: skip if already processed
        if is_lead_processed(website):
            print(f"  [-] Skipped: {website} (Already in leads.db)")
            continue
            
        print(f"  [-] Website found: {website}. Scraping & auditing...")
        target_email, website_text, has_viewport = scrape_website(website)
        
        audit_issues = passive_security_scan(website)
        if not has_viewport:
            audit_issues.append("Missing Mobile Viewport (Broken/un-optimized on mobile devices)")

        if audit_issues:
            print(f"  [!] Audit Findings: {', '.join(audit_issues)}")
            
        if not target_email:
            print(f"  [-] No email found on homepage or contact subpage.")
            record_lead(name, city, website, phone, None, audit_issues, status='NO_EMAIL')
            continue
            
        print(f"  [-] Found email: {target_email}. AI analyzing site...")
        email_body = generate_personalized_email(name, website, website_text, audit_issues)
        
        if send_live:
            send_email(target_email, f"Question about {name}", email_body)
            record_lead(name, city, website, phone, target_email, audit_issues, status='EMAILED', emailed=True)
            jitter_sec = random.uniform(45, 90)
            print(f"  [i] Deliverability jitter: waiting {jitter_sec:.1f}s before next contact...")
            time.sleep(jitter_sec)
        else:
            print(f"  [DRAFT - NOT SENT]\n  To: {target_email}\n  Subject: Question about {name}\n  Body: {email_body}\n")
            record_lead(name, city, website, phone, target_email, audit_issues, status='AUDITED')

if __name__ == "__main__":
    main()
