# Web Design Prospector Automation

A zero-dependency Python automation script for finding local businesses, analyzing their websites for security flaws, and generating personalized cold emails pitching a modern website redesign.

## Features
- **100% Free Lead Generation:** Uses OpenStreetMap (Overpass API) to find leads without needing an API key or credit card.
- **Passive Security Scanning:** Automatically detects missing security headers (CSP, HSTS, X-Frame-Options) on client websites.
- **AI Personalization:** Uses the Groq API (`openai/gpt-oss-20b`) to write highly personalized cold emails that leverage the scraped text and identified security vulnerabilities.
- **Zero Dependencies:** Built entirely with Python's standard library (`urllib`, `re`, `json`, `smtplib`). No `pip install` required!

## Getting Started
1. Get a free Groq API key from [Groq Console](https://console.groq.com/).
2. Create an App Password for your Gmail account.
3. Add your credentials to the `.env` file.
4. Run `python prospector.py`.
