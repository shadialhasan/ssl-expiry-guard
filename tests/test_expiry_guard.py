# -*- coding: utf-8 -*-
"""
Automated Test Suite for Fleet SSL Certificate Expiry Guard
Tests certificate validator, threshold alerts, socket mocking, and exports.
"""

import os
import csv
import json
import socket
import tempfile
import datetime
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

from expiry_guard import (
    parse_certificate_dict,
    get_ssl_certificate_details,
    get_ssl_expiry_days,
    audit_domains,
    export_json,
    export_csv,
    load_env
)

class TestSSLExpiryGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ref_time = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_certificate_validator_valid_long_lived(self):
        # Certificate expires in ~75 days
        synthetic_cert = {
            "notAfter": "Dec 15 12:00:00 2026 GMT",
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),))
        }

        result = parse_certificate_dict(
            synthetic_cert,
            domain="safe-domain.com",
            alert_threshold=15,
            warn_threshold=30,
            ref_time=self.ref_time
        )

        self.assertEqual(result["status"], "VALID")
        self.assertEqual(result["alert_level"], "OK")
        self.assertEqual(result["days_remaining"], 75)
        self.assertEqual(result["issuer"], "Let's Encrypt")
        self.assertIsNone(result["error"])

    def test_certificate_validator_warning_threshold(self):
        # Certificate expires in 20 days
        synthetic_cert = {
            "notAfter": "Oct 21 12:00:00 2026 GMT",
            "issuer": ((("organizationName", "DigiCert Inc"),),)
        }

        result = parse_certificate_dict(
            synthetic_cert,
            domain="warning-domain.com",
            alert_threshold=15,
            warn_threshold=30,
            ref_time=self.ref_time
        )

        self.assertEqual(result["status"], "EXPIRING")
        self.assertEqual(result["alert_level"], "WARNING")
        self.assertEqual(result["days_remaining"], 20)
        self.assertEqual(result["issuer"], "DigiCert Inc")

    def test_certificate_validator_critical_alert_threshold(self):
        # Certificate expires in 5 days
        synthetic_cert = {
            "notAfter": "Oct 06 12:00:00 2026 GMT",
            "issuer": ((("commonName", "Enterprise CA"),),)
        }

        result = parse_certificate_dict(
            synthetic_cert,
            domain="critical-domain.com",
            alert_threshold=15,
            warn_threshold=30,
            ref_time=self.ref_time
        )

        self.assertEqual(result["status"], "EXPIRING")
        self.assertEqual(result["alert_level"], "CRITICAL")
        self.assertEqual(result["days_remaining"], 5)
        self.assertEqual(result["issuer"], "Enterprise CA")

    def test_certificate_validator_expired(self):
        # Certificate expired 10 days ago
        synthetic_cert = {
            "notAfter": "Sep 21 12:00:00 2026 GMT",
            "issuer": ((("commonName", "Expired CA"),),)
        }

        result = parse_certificate_dict(
            synthetic_cert,
            domain="expired-domain.com",
            alert_threshold=15,
            warn_threshold=30,
            ref_time=self.ref_time
        )

        self.assertEqual(result["status"], "EXPIRED")
        self.assertEqual(result["alert_level"], "CRITICAL")
        self.assertEqual(result["days_remaining"], -10)

    def test_certificate_validator_missing_not_after(self):
        result = parse_certificate_dict(
            {},
            domain="corrupt-cert.com",
            ref_time=self.ref_time
        )
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["alert_level"], "UNKNOWN")
        self.assertIn("missing notAfter", result["error"])

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_mocked_tls_handshake_success(self, mock_socket, mock_context):
        # Mock SSL socket wrapping
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "notAfter": "Nov 15 12:00:00 2026 GMT",
            "issuer": ((("organizationName", "Cloudflare, Inc."),),)
        }
        mock_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        details = get_ssl_certificate_details("mocked-target.com")
        self.assertEqual(details["domain"], "mocked-target.com")
        self.assertIn(details["status"], ["VALID", "EXPIRING"])
        self.assertEqual(details["issuer"], "Cloudflare, Inc.")

    @patch("socket.create_connection")
    def test_mocked_socket_timeout_error_handling(self, mock_socket):
        mock_socket.side_effect = socket.timeout("Connection timed out")

        details = get_ssl_certificate_details("timed-out-host.com")
        self.assertEqual(details["status"], "ERROR")
        self.assertEqual(details["alert_level"], "ERROR")
        self.assertIn("timed out", details["error"])

    def test_export_to_json(self):
        records = [
            {
                "domain": "site-a.com",
                "port": 443,
                "status": "VALID",
                "alert_level": "OK",
                "days_remaining": 88,
                "not_after": "2026-12-28 12:00:00 UTC",
                "issuer": "Let's Encrypt",
                "error": None
            }
        ]

        out_path = Path(self.temp_dir.name) / "reports" / "ssl.json"
        saved = export_json(records, out_path)
        self.assertTrue(saved.exists())

        with saved.open(encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["domain"], "site-a.com")

    def test_export_to_csv(self):
        records = [
            {
                "domain": "site-b.com",
                "port": 443,
                "status": "EXPIRING",
                "alert_level": "CRITICAL",
                "days_remaining": 4,
                "not_after": "2026-10-05 12:00:00 UTC",
                "issuer": "GTS CA 1C3",
                "error": None
            }
        ]

        out_path = Path(self.temp_dir.name) / "reports" / "ssl.csv"
        saved = export_csv(records, out_path)
        self.assertTrue(saved.exists())

        with saved.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "site-b.com")
        self.assertEqual(rows[0]["alert_level"], "CRITICAL")

    def test_env_loader(self):
        env_file = Path(self.temp_dir.name) / ".env.test"
        env_file.write_text("ALERT_THRESHOLD_DAYS=25\nWARN_THRESHOLD_DAYS=45\n", encoding="utf-8")
        loaded = load_env(str(env_file))
        self.assertEqual(loaded.get("ALERT_THRESHOLD_DAYS"), "25")
        self.assertEqual(loaded.get("WARN_THRESHOLD_DAYS"), "45")


if __name__ == "__main__":
    unittest.main()
