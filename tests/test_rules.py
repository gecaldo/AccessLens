# Basic tests to make sure each demo rule is still being detected.

import unittest
from datetime import datetime, timezone

from src.loader import load_snapshot
from src.rules import audit_snapshot


class AccessLensRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_snapshot("data/sample_ad.json")
        cls.findings = audit_snapshot(
            cls.data,
            stale_days=90,
            now=datetime(2026, 10, 5, tzinfo=timezone.utc),
        )
        cls.rule_ids = {item["rule_id"] for item in cls.findings}

    def test_disabled_privileged_account(self):
        self.assertIn("R001", self.rule_ids)

    def test_non_expiring_password(self):
        self.assertIn("R002", self.rule_ids)

    def test_password_not_required(self):
        self.assertIn("R003", self.rule_ids)

    def test_stale_privileged_account(self):
        self.assertIn("R004", self.rule_ids)

    def test_multiple_privileged_groups(self):
        self.assertIn("R005", self.rule_ids)

    def test_nested_privilege_path(self):
        self.assertIn("R006", self.rule_ids)

    def test_guest_account_enabled(self):
        self.assertIn("R007", self.rule_ids)

    def test_nested_group_in_privileged_group(self):
        self.assertIn("R008", self.rule_ids)


if __name__ == "__main__":
    unittest.main()
