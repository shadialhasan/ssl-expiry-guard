# -*- coding: utf-8 -*-
"""
Fleet SSL Certificate Expiration Guard & Early Warning System
Author: Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
Phone: +963934005922
Copyright (c) 2026 MHD. Shadi AL-Hasan
"""

import os
import ssl
import csv
import json
import socket
import datetime
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

def load_env(env_path: Optional[str] = None) -> Dict[str, str]:
    """Lightweight .env loader without third-party dependencies."""
    target_path = Path(env_path) if env_path else Path(".env")
    env_vars = {}
    if not target_path.exists():
        return env_vars

    with target_path.open(encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            env_vars[key] = val
            if key not in os.environ:
                os.environ[key] = val
    return env_vars


def parse_certificate_dict(
    cert: Dict[str, Any],
    domain: str,
    port: int = 443,
    alert_threshold: int = 15,
    warn_threshold: int = 30,
    ref_time: Optional[datetime.datetime] = None
) -> Dict[str, Any]:
    """
    Parses a raw peer certificate dictionary and validates remaining lifespan
    against alert and warning thresholds.
    """
    if not cert or "notAfter" not in cert:
        return {
            "domain": domain,
            "port": port,
            "status": "ERROR",
            "alert_level": "UNKNOWN",
            "days_remaining": None,
            "not_after": None,
            "issuer": "Unknown",
            "subject": domain,
            "error": "Certificate missing notAfter field"
        }

    # Format: 'May 15 12:00:00 2026 GMT'
    not_after_str = cert["notAfter"]
    exp_date = datetime.datetime.strptime(
        not_after_str, "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=datetime.timezone.utc)

    now = ref_time if ref_time is not None else datetime.datetime.now(datetime.timezone.utc)
    remaining_delta = exp_date - now
    days = remaining_delta.days

    # Extract issuer Common Name / Organization
    org_name = None
    common_name = None
    for rdn in cert.get("issuer", ()):
        for key, val in rdn:
            if key == "organizationName":
                org_name = val
            elif key == "commonName":
                common_name = val
    issuer_name = org_name or common_name or "Unknown"

    # Determine status & alert severity
    if days < 0:
        status = "EXPIRED"
        alert_level = "CRITICAL"
    elif days <= alert_threshold:
        status = "EXPIRING"
        alert_level = "CRITICAL"
    elif days <= warn_threshold:
        status = "EXPIRING"
        alert_level = "WARNING"
    else:
        status = "VALID"
        alert_level = "OK"

    return {
        "domain": domain,
        "port": port,
        "status": status,
        "alert_level": alert_level,
        "days_remaining": days,
        "not_after": exp_date.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "issuer": issuer_name,
        "subject": domain,
        "error": None
    }


def get_ssl_certificate_details(
    domain: str,
    port: int = 443,
    timeout: float = 5.0,
    alert_threshold: int = 15,
    warn_threshold: int = 30
) -> Dict[str, Any]:
    """Performs TLS handshake with target host to inspect SSL certificate."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return parse_certificate_dict(
                    cert,
                    domain=domain,
                    port=port,
                    alert_threshold=alert_threshold,
                    warn_threshold=warn_threshold
                )
    except Exception as e:
        return {
            "domain": domain,
            "port": port,
            "status": "ERROR",
            "alert_level": "ERROR",
            "days_remaining": None,
            "not_after": None,
            "issuer": "Unknown",
            "subject": domain,
            "error": str(e)
        }


def get_ssl_expiry_days(domain: str, port: int = 443, timeout: float = 5.0) -> int:
    """Backward-compatible helper returning days remaining or raising error."""
    details = get_ssl_certificate_details(domain, port, timeout=timeout)
    if details["error"]:
        raise ConnectionError(f"TLS inspection failed for {domain}: {details['error']}")
    return details["days_remaining"]


def export_json(results: List[Dict[str, Any]], output_path: Path | str) -> Path:
    """Exports inspection findings to JSON."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return dest


def export_csv(results: List[Dict[str, Any]], output_path: Path | str) -> Path:
    """Exports inspection findings to CSV."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "domain",
        "port",
        "status",
        "alert_level",
        "days_remaining",
        "not_after",
        "issuer",
        "error"
    ]
    with dest.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    return dest


def audit_domains(
    domains: List[str],
    port: int = 443,
    alert_threshold: int = 15,
    warn_threshold: int = 30,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Audits a fleet of target domains and reports status to terminal."""
    target_list = [d.strip() for d in domains if d and d.strip()]
    print(f"[*] Auditing SSL validity for {len(target_list)} domains...")
    print(f"[*] Thresholds: Critical <= {alert_threshold} days | Warning <= {warn_threshold} days")
    print("=" * 75)

    results = []
    for d in target_list:
        res = get_ssl_certificate_details(
            d,
            port=port,
            timeout=timeout,
            alert_threshold=alert_threshold,
            warn_threshold=warn_threshold
        )
        results.append(res)

        level = res["alert_level"]
        domain_fmt = f"{res['domain']}:{res['port']}"

        if level == "CRITICAL":
            if res["status"] == "EXPIRED":
                print(f"[CRITICAL ALERT] {domain_fmt:30} -> EXPIRED ({res['days_remaining']} days ago)!")
            else:
                print(f"[CRITICAL ALERT] {domain_fmt:30} -> Expires in {res['days_remaining']} days! (Issuer: {res['issuer']})")
        elif level == "WARNING":
            print(f"[WARNING ALERT]  {domain_fmt:30} -> Expires in {res['days_remaining']} days. (Issuer: {res['issuer']})")
        elif level == "OK":
            print(f"[OK]             {domain_fmt:30} -> Valid for {res['days_remaining']} days. (Issuer: {res['issuer']})")
        else:
            print(f"[ERROR]          {domain_fmt:30} -> Failed to inspect ({res['error']})")

    print("=" * 75)
    return results


def main():
    load_env()
    parser = argparse.ArgumentParser(
        description="Fleet SSL Certificate Expiration Guard & Early Warning System"
    )
    parser.add_argument(
        "--domains", "-d",
        nargs="+",
        help="Space-separated list of domains or comma-separated string"
    )
    parser.add_argument("--file", "-f", help="Text file containing domains list (one per line)")
    parser.add_argument(
        "--alert-threshold", "-a",
        type=int,
        default=int(os.getenv("ALERT_THRESHOLD_DAYS", 15)),
        help="Critical alert threshold in days before expiry (default: 15)"
    )
    parser.add_argument(
        "--warn-threshold", "-w",
        type=int,
        default=int(os.getenv("WARN_THRESHOLD_DAYS", 30)),
        help="Warning threshold in days before expiry (default: 30)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.getenv("DEFAULT_PORT", 443)),
        help="Port number to connect to (default: 443)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=float(os.getenv("CHECK_TIMEOUT", 5.0)),
        help="Network socket timeout in seconds (default: 5.0)"
    )
    parser.add_argument("--export-json", help="Path to export results as JSON")
    parser.add_argument("--export-csv", help="Path to export results as CSV")
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default=os.getenv("EXPORT_FORMAT", "table"),
        help="Console output format (table, json, csv)"
    )

    args = parser.parse_args()

    targets = []
    if args.domains:
        for item in args.domains:
            targets.extend([x.strip() for x in item.split(",") if x.strip()])
    elif args.file:
        targets.extend(Path(args.file).read_text(encoding="utf-8").splitlines())
    elif os.getenv("DOMAINS"):
        targets.extend([x.strip() for x in os.getenv("DOMAINS", "").split(",") if x.strip()])

    if not targets:
        targets = ["google.com", "github.com", "cloudflare.com"]

    results = audit_domains(
        domains=targets,
        port=args.port,
        alert_threshold=args.alert_threshold,
        warn_threshold=args.warn_threshold,
        timeout=args.timeout
    )

    if args.export_json:
        saved = export_json(results, args.export_json)
        print(f"\n[+] Successfully exported JSON report to: {saved}")

    if args.export_csv:
        saved = export_csv(results, args.export_csv)
        print(f"[+] Successfully exported CSV report to: {saved}")

    if args.format == "json" and not args.export_json:
        print("\n=== JSON OUTPUT ===")
        print(json.dumps(results, indent=2))
    elif args.format == "csv" and not args.export_csv:
        print("\n=== CSV OUTPUT ===")
        temp_csv = Path("temp_ssl.csv")
        export_csv(results, temp_csv)
        print(temp_csv.read_text(encoding="utf-8"))
        temp_csv.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
