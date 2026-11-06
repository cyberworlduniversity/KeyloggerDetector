import unittest
from unittest.mock import patch

import keylogger_detector


class DetectorTests(unittest.TestCase):
    def test_suspicious_name_matching_is_case_insensitive(self):
        self.assertTrue(keylogger_detector.is_suspicious("KeyLoggerService"))
        self.assertFalse(keylogger_detector.is_suspicious("normal-browser"))

    def test_empty_names_are_not_suspicious(self):
        self.assertFalse(keylogger_detector.is_suspicious(""))
        self.assertFalse(keylogger_detector.is_suspicious(None))

    def test_alert_records_known_levels(self):
        with patch("builtins.print"):
            keylogger_detector.ALERTS.clear()
            keylogger_detector.alert("WARNING", "test warning")
        self.assertEqual(keylogger_detector.ALERTS[-1]["level"], "WARNING")
        self.assertEqual(keylogger_detector.ALERTS[-1]["message"], "test warning")


if __name__ == "__main__":
    unittest.main()
