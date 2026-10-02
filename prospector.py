# ponytail: Zero dependencies. Using stdlib urllib, json, smtplib, and regex to avoid bloated requests, beautifulsoup, or SDKs.
# 1. Finds leads via Google Places
# 2. Scrapes homepage for email & text
# 3. Asks Gemini AI to write a personalized cold email
# 4. Sends it via SMTP

import urllib.request
import urllib.parse
import json
import smtplib
import re
import os
import socket
import ipaddress
import ssl
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

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER") or os.environ.get("GMAILUSER", "")
SMTP_PASS = (os.environ.get("SMTP_PASS") or os.environ.get("GMAILSMTP", "")).replace(" ", "")

def find_places_free(city, business_type):
    """Finds businesses using the free Overpass API (OpenStreetMap). No API key required!"""
    # Map common search terms to OSM tags
    term = business_type.lower()
    tag = f'name~"{term}",i' # Default to searching by name
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

def is_safe_url(url):
    """Allows only HTTP(S) destinations resolving to public IP addresses."""
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ('http', 'https') or not p.hostname:
            return False
        for _, _, _, _, sockaddr in socket.getaddrinfo(p.hostname, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if not ip.is_global:
                return False
        return True
    except Exception:
        return False

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ensures HTTP redirects cannot escape to non-global or invalid destinations."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_url(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

urllib.request.install_opener(urllib.request.build_opener(SafeRedirectHandler))

def scrape_website(url):
    """Scrapes the homepage for an email address and raw text content."""
    if not is_safe_url(url):
        print(f"  [!] Skipped unsafe or invalid URL: {url}")
        return None, ""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            if response.headers.get_content_type() not in ('text/html', 'application/xhtml+xml', 'text/plain'):
                return None, ""
            html = response.read(100000).decode('utf-8', errors='ignore')
            
            # Email extraction: prioritize mailto links and preserve document order
            mailtos = re.findall(r'mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', html, re.I)
            raw_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html)
            emails = [e for e in dict.fromkeys(mailtos + raw_emails) if not e.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))]
            
            # Naive text extraction
            text_content = re.sub('<[^<]+?>', ' ', html)
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            
            return emails[0] if emails else None, text_content[:2000]
    except Exception as e:
        print(f"  [!] Could not scrape {url}: {e}")
        return None, ""

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
                    if vals and '*' not in vals:
                        has_frame_ancestors = True
                    break
            has_framing_protection = has_frame_ancestors or (xfo in ('DENY', 'SAMEORIGIN'))
            if not has_framing_protection:
                missing.append("Anti-Clickjacking (X-Frame-Options / frame-ancestors)")
            return missing
    except Exception:
        return []

def generate_personalized_email(business_name, website_url, website_text, missing_security):
    """Uses Groq API to write a personalized cold email based on website flaws and security risks."""
    
    security_prompt = ""
    if missing_security:
        security_prompt = f"CRITICAL: Their website is missing basic security protections: {', '.join(missing_security)}. They are vulnerable to attacks."

    prompt = f"""
    Write a short, casual cold email to {business_name}. 
    Their website is {website_url}. Based on this text from their homepage: "{website_text}", 
    they likely have an outdated or poorly optimized site.
    {security_prompt}
    Pitch a modern, SECURE website redesign. Keep it under 4 sentences. Sound human, not corporate.
    """

    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = json.dumps({
        "model": "openai/gpt-oss-20b",
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
        return f"Hey {business_name}, I noticed your website might need an update. Let's chat!"

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

def main():
    print("--- 100% Free Lead Generation ---")
    city = input("Enter the city (e.g., 'Austin'): ").strip()
    business_type = input("Enter the business type (e.g., 'plumber', 'dentist'): ").strip()
    
    print(f"\nSearching for '{business_type}' in '{city}' using OpenStreetMap (Free)...\n")
    
    places = find_places_free(city, business_type)
    
    if not places:
        print("No places found. Try a larger city or a different business type.")
        return

    for place in places[:10]: # Limit to 10 for testing
        name = place.get('name')
        print(f"--- Processing: {name} ---")
        
        website = place.get('website')
        phone = place.get('phone', 'N/A')
        
        if not website:
            print(f"  [-] NO WEBSITE. (Phone: {phone})")
            print(f"  [-] Since they have no website, an email address isn't publicly listed. Calling them is the best strategy.")
            continue

        if "://" not in website:
            website = f"https://{website}"
            
        print(f"  [-] Website found: {website}. Scraping...")
        target_email, website_text = scrape_website(website)
        
        missing_sec = passive_security_scan(website)
        if missing_sec:
            print(f"  [!] Security Vulnerabilities Found: {', '.join(missing_sec)}")
            
        if not target_email:
            print(f"  [-] No email found on homepage.")
            continue
            
        print(f"  [-] Found email: {target_email}. AI analyzing site...")
        email_body = generate_personalized_email(name, website, website_text, missing_sec)
        
        print(f"  [DRAFT - NOT SENT]\n  To: {target_email}\n  Subject: Question about {name}\n  Body: {email_body}\n")
        # To actually send, uncomment the line below:
        # send_email(target_email, f"Question about {name}", email_body)

if __name__ == "__main__":
    main()
