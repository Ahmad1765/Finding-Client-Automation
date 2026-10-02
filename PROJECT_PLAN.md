# Project Plan: Web Design Client Prospecting Automation

## 1. Goal
To build a custom, lightweight Python automation that replaces expensive SaaS prospecting tools. The system will find local businesses, analyze their web presence, and generate/send highly personalized cold emails pitching web design services.

## 2. Target Audiences
1. **Businesses with BAD websites**: We scrape their homepage, use AI to critique the content/structure, and send a personalized email pointing out specific flaws and pitching a redesign.
2. **Businesses with NO websites**: We detect the absence of a website. *(Note: Since they lack a domain, finding an email is heavily constrained. The system will flag their phone numbers for manual follow-up or SMS outreach).*

## 3. Tech Stack (The "Ponytail" Approach)
To keep the system robust, lightning-fast, and completely free of dependency hell, we are exclusively using the Python Standard Library.
- **Language**: Python 3.10+
- **Lead Generation**: OpenStreetMap via Overpass API (called via `urllib.request`). 100% free, no API keys needed.
- **Web Scraping**: Native `urllib` for fetching HTML + Native `re` (Regex) for extracting emails and stripping tags. No `BeautifulSoup` or `Selenium` overhead.
- **AI Analysis & Personalization**: Groq API (e.g., Llama 3, called via pure REST `urllib` using their OpenAI-compatible endpoint).
- **Email Delivery**: Native `smtplib` + `email.message`.

## 4. Pipeline Architecture
The automation executes in a 5-step linear pipeline within `prospector.py`:

1. **Search**: User inputs a city and business type (e.g., "Austin", "Plumber"). Script hits the free Overpass API.
2. **Enrichment**: Overpass returns the business names, websites, and phone numbers natively.
3. **Scrape**: 
   - *If no website*: Logs the phone number for manual outreach and skips.
   - *If website exists*: Downloads the homepage HTML. Runs regex to extract target emails. Strips HTML tags to extract readable text.
4. **AI Generation**: Sends the scraped text to the Groq API. The LLM is prompted to write a short, human-sounding cold email highlighting issues on the site.
5. **Outreach**: Authenticates via SMTP and fires off the personalized email.

## 5. Prerequisites & API Keys Needed (Research Phase)
Before we can run this live, you will need to acquire three free credentials:

1. **Groq API Key**: 
   - Go to the Groq Console (console.groq.com).
   - Create a free API key.
2. **SMTP Credentials**:
   - If using Gmail: Enable 2-Step Verification on a Google Account, then generate an **App Password** for the script to use.

## 6. Known Limitations to Address
- **Email Scraping**: Regex scraping the homepage won't find emails hidden behind contact forms or JavaScript. It will only find publicly visible `mailto:` or raw text emails.
- **Rate Limits**: The free tiers of Groq and Overpass API have limits (e.g., Overpass expects a fair use of queries, Groq has strict RPM limits). The script will need basic throttling (e.g., `time.sleep`) if scaling up.
