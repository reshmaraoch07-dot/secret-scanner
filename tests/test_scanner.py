"""
Automated Test Suite for Secret Scanner
Verifies core scanner functionality, regex detection, false positive handling,
masking security, and exit codes.
"""

import unittest
from pathlib import Path
from scanner import scan_content, scan_line, scan_directory
from patterns import mask_secret, SEVERITY_HIGH, SEVERITY_MEDIUM


class TestSecretScanner(unittest.TestCase):

    def test_1_clean_file_passes(self):
        """Test 1: Clean source code file should pass with 0 secrets detected."""
        clean_code = """
def calculate_total(price, tax_rate):
    # Calculate order total with tax
    total = price * (1 + tax_rate)
    return round(total, 2)

user_name = "Alice"
age = 25
print("User profile loaded successfully.")
"""
        result = scan_content(clean_code, "clean_app.py")
        self.assertTrue(result["passed"])
        self.assertEqual(result["total_secrets"], 0)
        self.assertEqual(len(result["findings"]), 0)

    def test_2_detect_password(self):
        """Test 2: File containing password assignment should be detected."""
        password_code = 'admin_password = "supersecretpass123"'
        result = scan_content(password_code, "config.py")
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["total_secrets"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], SEVERITY_HIGH)
        self.assertIn("Password", finding["type"])

    def test_3_detect_api_key(self):
        """Test 3: File containing API key assignment should be detected."""
        api_code = 'API_KEY = "sk_live_998877665544332211"'
        result = scan_content(api_code, "services.js")
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["total_secrets"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], SEVERITY_HIGH)
        self.assertIn("API Key", finding["type"])

    def test_4_detect_token(self):
        """Test 4: File containing access token should be detected."""
        token_code = 'access_token = "bearer_eyJhbGciOiJIUzI1NiJ9"'
        result = scan_content(token_code, "auth.py")
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["total_secrets"], 1)
        finding = result["findings"][0]
        self.assertIn("Token", finding["type"])

    def test_5_multiple_secrets(self):
        """Test 5: Multiple secrets in one file should all be detected."""
        multi_code = """
# Application credentials file
DATABASE_URL = "postgres://admin:dbpassword123@localhost:5432/mydb"
SECRET_KEY = "super_secret_jwt_key_999"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
"""
        result = scan_content(multi_code, "settings.env")
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["total_secrets"], 3)

    def test_6_avoid_false_positives(self):
        """Test 6: Normal UI text or comments mentioning 'password' shouldn't trigger false positives."""
        safe_comment_code = """
# Please remember to set your password in the environment variables.
print("Please enter your password below:")
input_label = "<label>Password</label>"
"""
        result = scan_content(safe_comment_code, "login_view.py")
        self.assertTrue(result["passed"])
        self.assertEqual(result["total_secrets"], 0)

    def test_7_secret_value_masked(self):
        """Test 7: Exposed secret value must be safely masked in results."""
        secret_raw = "my_top_secret_password_2026"
        masked = mask_secret(secret_raw)
        
        # Secret value must NOT appear unmasked in masked string
        self.assertNotIn(secret_raw, masked)
        self.assertTrue("*" in masked)
        self.assertEqual(masked, "my*************************")

    def test_8_aws_access_key_detection(self):
        """Test 8: AWS AKIA key detection."""
        aws_code = 'AWS_KEY_ID = "AKIA1234567890ABCDEF"'
        result = scan_content(aws_code, "cloud.py")
        self.assertFalse(result["passed"])
        self.assertEqual(result["total_secrets"], 1)
        self.assertEqual(result["findings"][0]["type"], "AWS Access Key")


if __name__ == "__main__":
    unittest.main()
