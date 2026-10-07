#!/usr/bin/env python3
"""
Serper.dev Interactive Dork Finder
----------------------------------
A tool for legitimate security research and responsible disclosure.
Searches for publicly exposed sensitive information using advanced Google-style dorks.

Usage:
    python dork_finder.py

Requirements:
    pip install requests

Get a free API key at: https://serper.dev
"""

import os
import requests
from urllib.parse import urlparse
from datetime import datetime
import getpass

# ====================== CONFIG ======================
OUTPUT_FILE = "exposed_findings.txt"
NUM_RESULTS = 10          # results per dork (adjust if needed)
# ====================================================

# Advanced dork collections
DORK_CATEGORIES = {
    "1": {
        "name": "Credentials & Secrets",
        "dorks": [
            'filetype:env "DB_PASSWORD" OR "API_KEY" OR "SECRET"',
            'filetype:json "api_key" OR "apikey" OR "secret_key"',
            'filetype:yml OR filetype:yaml "password:" OR "secret:"',
            'ext:ini "password" OR "pwd"',
            '"aws_access_key_id" OR "AKIA"',
            'filetype:xml "password" password',
        ]
    },
    "2": {
        "name": "Configuration & Backup Files",
        "dorks": [
            'filetype:env',
            'filetype:sql "CREATE TABLE" OR "INSERT INTO"',
            'ext:bak OR ext:old OR ext:backup',
            'filetype:cfg OR filetype:conf "password"',
            'filetype:log "password" OR "passwd"',
            '"index of" "backup"',
        ]
    },
    "3": {
        "name": "Admin / Login Panels",
        "dorks": [
            'inurl:admin "login" OR "dashboard"',
            'inurl:administrator',
            'inurl:wp-admin',
            'inurl:phpmyadmin',
            'intitle:"admin login" OR intitle:"administrator login"',
            'inurl:login "admin"',
        ]
    },
    "4": {
        "name": "Database Dumps & Sensitive Data",
        "dorks": [
            'filetype:sql "INSERT INTO users"',
            'filetype:sql "password"',
            'ext:sql "dump"',
            'filetype:csv "password" OR "email"',
            'filetype:xlsx "password" OR "ssn"',
            '"database dump" filetype:sql',
        ]
    },
    "5": {
        "name": "Sensitive Documents",
        "dorks": [
            'filetype:pdf "confidential" OR "internal only"',
            'filetype:pdf "not for distribution"',
            'filetype:doc OR filetype:docx "password"',
            'filetype:xls OR filetype:xlsx "salary" OR "employee"',
            'intitle:"confidential" filetype:pdf',
            '"private and confidential" filetype:pdf',
        ]
    },
    "6": {
        "name": "Open Directories & Indexes",
        "dorks": [
            'intitle:"index of" "parent directory"',
            'intitle:"index of" password',
            'intitle:"index of" backup',
            'intitle:"index of" .env',
            'intitle:"index of" config',
            '"index of /" "wp-content"',
        ]
    },
    "7": {
        "name": "API Endpoints & Keys",
        "dorks": [
            'inurl:api "key" OR "token"',
            'filetype:json "api_key"',
            'inurl:"/v1/" OR inurl:"/api/v"',
            '"Authorization: Bearer"',
            'filetype:js "apiKey" OR "api_key"',
            'inurl:swagger OR inurl:api-docs',
        ]
    },
    "8": {
        "name": "Exposed Card / Payment Details",
        "dorks": [
            'filetype:txt "card number" OR "credit card" OR "cvv"',
            'filetype:csv "card number" OR "cvv" OR "expiry"',
            'filetype:log "card" "cvv" OR "cvc"',
            'filetype:sql "card_number" OR "credit_card" OR "cvv"',
            '"card number" "cvv" filetype:txt OR filetype:log OR filetype:csv',
            'filetype:xlsx "card number" OR "cvv" OR "exp date"',
            '"pan" "cvv" OR "cvc" filetype:txt OR filetype:csv',
            'intext:"cardholder" "cvv" OR "cvc"',
            'filetype:pdf "credit card" "cvv" OR "cvc"',
            '"visa" "mastercard" "cvv" filetype:txt OR filetype:log',
        ]
    },
    "9": {
        "name": "Exposed SSN + Bank & Routing Numbers",
        "dorks": [
            # SSN related
            'filetype:txt "ssn" OR "social security"',
            'filetype:csv "ssn" OR "social security number"',
            'filetype:xlsx "ssn" OR "social security"',
            'filetype:sql "ssn" OR "social_security"',
            '"social security number" filetype:txt OR filetype:csv OR filetype:log',
            'filetype:pdf "social security number" OR "ssn"',

            # Bank account + routing numbers
            'filetype:txt "routing number" OR "account number"',
            'filetype:csv "routing number" OR "bank account"',
            'filetype:xlsx "routing" "account number"',
            '"routing number" "account number" filetype:txt OR filetype:csv',
            'filetype:sql "routing_number" OR "bank_account"',
            '"ABA" "routing" filetype:txt OR filetype:csv',
            'filetype:log "routing number" OR "account number"',
            '"bank account" "routing" filetype:pdf OR filetype:doc',
        ]
    },
    "10": {
        "name": "Exposed SMTP Credentials",
        "dorks": [
            'filetype:env "SMTP" OR "MAIL_PASSWORD" OR "MAIL_HOST"',
            'filetype:env "SMTP_PASSWORD" OR "SMTP_USER" OR "SMTP_HOST"',
            '"smtp_password" OR "smtp_user" OR "smtp_host" filetype:env OR filetype:yml OR filetype:yaml',
            'filetype:yml OR filetype:yaml "smtp" "password"',
            'filetype:ini "smtp" "password" OR "mail"',
            '"mail.smtp" "password" filetype:txt OR filetype:log OR filetype:conf',
            'filetype:php "smtp" "password" OR "mail_password"',
            '"SMTP_PASS" OR "MAIL_PASS" OR "EMAIL_PASSWORD"',
            'filetype:json "smtp" "password" OR "smtpPassword"',
            '"outgoing server" "password" smtp OR mail',
        ]
    },
    "11": {
        "name": "Exposed cPanel Credentials",
        "dorks": [
            'inurl:cpanel "login" OR "password"',
            'intitle:"cPanel Login" OR intitle:"cPanel"',
            'inurl:":2082" OR inurl:":2083" OR inurl:":2086" OR inurl:":2087"',
            '"cpanel" "password" filetype:txt OR filetype:log OR filetype:env',
            'filetype:env "CPANEL" OR "cpanel_user" OR "cpanel_pass"',
            '"cpanel username" OR "cpanel password" OR "cpanel login"',
            'inurl:cpanel intitle:"login"',
            'filetype:txt "cpanel" "password" OR "whm"',
            '"whm" "password" OR "cpanel" "root" password',
            'inurl:/cpanel/ OR inurl:/webmail/ "password"',
        ]
    },
    "12": {
        "name": "Exposed Social Media Credentials & Tokens",
        "dorks": [
            # Facebook / Meta
            'filetype:env "FACEBOOK" OR "FB_APP" OR "FB_ACCESS_TOKEN"',
            '"facebook" "access_token" OR "app_secret" filetype:env OR filetype:json OR filetype:yml',
            'filetype:json "facebook" "access_token" OR "fb_token"',

            # Twitter / X
            'filetype:env "TWITTER" OR "TWITTER_API" OR "TWITTER_BEARER"',
            '"twitter" "api_key" OR "api_secret" OR "bearer_token" OR "access_token"',
            'filetype:env "X_API" OR "TWITTER_CONSUMER"',

            # Instagram
            'filetype:env "INSTAGRAM" OR "IG_USERNAME" OR "IG_PASSWORD"',
            '"instagram" "sessionid" OR "csrftoken" OR "access_token"',
            'filetype:json "instagram" "access_token" OR "session"',

            # LinkedIn / others
            'filetype:env "LINKEDIN" OR "LINKEDIN_CLIENT"',
            '"linkedin" "access_token" OR "client_secret"',
            'filetype:env "DISCORD_TOKEN" OR "TELEGRAM_BOT" OR "SLACK_TOKEN"',
            '"discord" "bot_token" OR "telegram" "bot_token" OR "slack" "bot_token"',
        ]
    },
    "13": {
        "name": "Exposed Bank-Specific Data (Citi, Chase, etc.)",
        "dorks": [
            # Chase
            '"chase" "account number" OR "routing number" filetype:txt OR filetype:csv OR filetype:xlsx',
            '"chase bank" "account" "routing" OR "aba"',
            'filetype:pdf "chase" "account number" OR "routing"',

            # Citi / Citibank
            '"citi" OR "citibank" "account number" OR "routing number"',
            '"citibank" "account" "routing" filetype:txt OR filetype:csv OR filetype:pdf',
            'filetype:xlsx "citi" "account" OR "routing"',

            # Bank of America
            '"bank of america" OR "bofa" "account number" OR "routing number"',
            '"bank of america" "routing" filetype:txt OR filetype:csv OR filetype:pdf',

            # Wells Fargo
            '"wells fargo" "account number" OR "routing number"',
            '"wells fargo" "routing" filetype:txt OR filetype:csv OR filetype:xlsx',

            # Generic + other major banks
            '"capital one" OR "us bank" OR "pnc" "account number" OR "routing"',
            '"td bank" OR "hsbc" OR "barclays" "account number" OR "routing number"',
            'filetype:sql "chase" OR "citi" OR "wells_fargo" "account"',
        ]
    },
}


def get_api_key() -> str:
    """Get API key from environment or ask the user interactively."""
    key = os.getenv("SERPER_API_KEY")
    if key:
        print("✓ Found SERPER_API_KEY in environment variables.")
        return key

    print("\nNo API key found in environment variables.")
    print("You can get a free key at: https://serper.dev")
    key = getpass.getpass("Paste your Serper API key (input is hidden): ").strip()

    if not key:
        print("No key provided. Exiting.")
        exit(1)

    return key


def search_serper(api_key: str, query: str) -> list:
    """Send a dork query to Serper and return organic results."""
    url = "https://google.serper.dev/search"
    headers = {
        "X-API-KEY": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "q": query,
        "num": NUM_RESULTS
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("organic", [])
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request error: {e}")
        return []


def extract_domain(url: str) -> str:
    """Extract the clean domain from a URL."""
    try:
        return urlparse(url).netloc
    except Exception:
        return "unknown"


def save_findings(query: str, results: list):
    """Append search results to the output text file."""
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*75}\n")
        f.write(f"Query : {query}\n")
        f.write(f"Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*75}\n\n")

        if not results:
            f.write("No results found.\n")
            return

        for i, item in enumerate(results, 1):
            title   = item.get("title", "No title")
            link    = item.get("link", "")
            snippet = item.get("snippet", "")
            domain  = extract_domain(link)

            f.write(f"[{i}] Domain  : {domain}\n")
            f.write(f"    Title   : {title}\n")
            f.write(f"    URL     : {link}\n")
            f.write(f"    Snippet : {snippet}\n\n")


def show_menu():
    """Display the interactive category menu."""
    print("\n" + "="*55)
    print("          EXPOSED INFORMATION FINDER")
    print("="*55)
    print("Select the type of information you want to search for:\n")

    for key, cat in DORK_CATEGORIES.items():
        print(f"  {key}. {cat['name']}")

    print("  0. Exit")
    print("="*55)


def main():
    print("Serper.dev Interactive Dork Finder")
    print("For legitimate security research & responsible disclosure only.\n")

    api_key = get_api_key()

    # Clear previous results at the start of a session
    open(OUTPUT_FILE, "w", encoding="utf-8").close()

    while True:
        show_menu()
        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            print("Exiting. Stay ethical!")
            break

        if choice not in DORK_CATEGORIES:
            print("Invalid choice. Please try again.")
            continue

        category = DORK_CATEGORIES[choice]
        print(f"\n→ Selected: {category['name']}")
        print(f"→ Running {len(category['dorks'])} advanced dorks...\n")

        for dork in category["dorks"]:
            print(f"Searching: {dork}")
            results = search_serper(api_key, dork)
            save_findings(dork, results)
            print(f"  → {len(results)} results saved")

        print(f"\n✓ Finished. All findings saved to: {OUTPUT_FILE}")
        print("Review the file carefully before contacting any organization.\n")

        again = input("Do you want to search another category? (y/n): ").strip().lower()
        if again != "y":
            print("Done. Remember: Responsible disclosure only.")
            break


if __name__ == "__main__":
    main()
