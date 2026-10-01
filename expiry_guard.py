# -*- coding: utf-8 -*-
"""
Fleet SSL Certificate Expiration Guard & Early Warning System
Author: Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
Phone: +963934005922
Copyright (c) 2026 MHD. Shadi AL-Hasan
"""

import ssl
import socket
import datetime
import argparse
from pathlib import Path

def get_ssl_expiry_days(domain: str, port: int = 443) -> int:
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            not_after = cert['notAfter']
            # Format: 'May 15 12:00:00 2026 GMT'
            exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            remaining = exp_date - datetime.datetime.now(datetime.timezone.utc)
            return remaining.days

def audit_domains(domains: list, alert_threshold=15):
    print(f"[*] Auditing SSL validity for {len(domains)} domains...")
    print("=" * 60)
    for d in domains:
        d = d.strip()
        if not d:
            continue
        try:
            days = get_ssl_expiry_days(d)
            if days <= alert_threshold:
                print(f"[CRITICAL ALERT] {d:30} -> Expires in {days} days!")
            else:
                print(f"[OK]             {d:30} -> Valid for {days} days.")
        except Exception as e:
            print(f"[ERROR]          {d:30} -> Failed to inspect ({e})")
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Check SSL expiry dates across domains.")
    parser.add_argument("--domains", "-d", nargs="+", help="Space-separated list of domains")
    parser.add_argument("--file", "-f", help="Text file containing domains list")
    args = parser.parse_args()

    targets = []
    if args.domains:
        targets.extend(args.domains)
    if args.file:
        targets.extend(Path(args.file).read_text(encoding="utf-8").splitlines())

    if not targets:
        targets = ["google.com", "github.com", "cloudflare.com"]

    audit_domains(targets)

if __name__ == "__main__":
    main()
