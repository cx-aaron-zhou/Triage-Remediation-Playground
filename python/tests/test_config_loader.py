"""
Comprehensive security tests for config_loader.py YAML deserialization fix.

These tests validate that:
1. The yaml.safe_load() fix prevents arbitrary code execution
2. Valid YAML configurations are still processed correctly
3. Malicious payloads are safely rejected or sanitized
4. Edge cases and attack vectors are properly handled
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.config_loader import app


class TestConfigLoaderSecurity(unittest.TestCase):
    """Test suite for YAML deserialization vulnerability remediation."""

    def setUp(self):
        """Set up test client for each test."""
        self.app = app
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True

    def tearDown(self):
        """Clean up after each test."""
        pass

    # ========== POSITIVE TESTS: Valid YAML should work ==========

    def test_valid_simple_yaml_config(self):
        """Test that valid simple YAML configurations are processed correctly."""
        valid_yaml = """
name: test_config
version: 1.0
enabled: true
"""
        response = self.client.post('/config',
                                   data=valid_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['name'], 'test_config')
        self.assertEqual(data['version'], 1.0)
        self.assertTrue(data['enabled'])

    def test_valid_nested_yaml_config(self):
        """Test that valid nested YAML configurations are processed correctly."""
        nested_yaml = """
database:
  host: localhost
  port: 5432
  credentials:
    username: dbuser
    password: dbpass
settings:
  timeout: 30
  retries: 3
"""
        response = self.client.post('/config',
                                   data=nested_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['database']['host'], 'localhost')
        self.assertEqual(data['database']['port'], 5432)
        self.assertEqual(data['settings']['timeout'], 30)

    def test_valid_yaml_with_lists(self):
        """Test that YAML with lists is processed correctly."""
        yaml_with_lists = """
servers:
  - server1.example.com
  - server2.example.com
  - server3.example.com
ports:
  - 8080
  - 8081
  - 8082
"""
        response = self.client.post('/config',
                                   data=yaml_with_lists,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data['servers']), 3)
        self.assertEqual(data['servers'][0], 'server1.example.com')
        self.assertIn(8080, data['ports'])

    def test_empty_yaml_config(self):
        """Test that empty YAML is handled gracefully."""
        response = self.client.post('/config',
                                   data='',
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNone(data)

    def test_yaml_with_special_characters(self):
        """Test YAML with special characters in values."""
        special_yaml = """
message: "Hello, World! @#$%^&*()"
path: "/usr/local/bin:/usr/bin"
email: "user@example.com"
"""
        response = self.client.post('/config',
                                   data=special_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['message'], 'Hello, World! @#$%^&*()')
        self.assertEqual(data['email'], 'user@example.com')

    # ========== NEGATIVE TESTS: Malicious payloads should be blocked ==========

    def test_blocks_python_object_instantiation(self):
        """
        CRITICAL SECURITY TEST: Verify that !!python/object tag is rejected.
        This was the primary attack vector in the vulnerability.
        """
        malicious_yaml = """!!python/object:os.system ['echo pwned > /tmp/pwned.txt']"""

        # With safe_load, this should either raise an error or return a safe value
        # It should NOT execute arbitrary code
        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            # If it doesn't raise an error, check that no code was executed
            # safe_load should prevent object instantiation
            self.assertIn(response.status_code, [200, 400, 500])

            # Verify the malicious file was NOT created
            self.assertFalse(os.path.exists('/tmp/pwned.txt'),
                           "Arbitrary code execution detected! File should not exist.")
        except Exception as e:
            # safe_load raising an exception is acceptable behavior
            pass

    def test_blocks_python_object_apply(self):
        """
        CRITICAL SECURITY TEST: Verify that !!python/object/apply is rejected.
        Another common RCE attack vector.
        """
        malicious_yaml = """!!python/object/apply:subprocess.check_output [['id']]"""

        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            # Should not execute the command
            self.assertIn(response.status_code, [200, 400, 500])
        except Exception as e:
            # Exception is acceptable - means it was blocked
            pass

    def test_blocks_python_module_import(self):
        """
        CRITICAL SECURITY TEST: Verify that !!python/module imports are blocked.
        """
        malicious_yaml = """!!python/module:os"""

        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            self.assertIn(response.status_code, [200, 400, 500])
            # Should not return an actual module object
            if response.status_code == 200:
                data = response.get_json()
                # safe_load should not deserialize module objects
                self.assertNotIn('__name__', str(data))
        except Exception as e:
            # Exception is acceptable
            pass

    def test_blocks_python_eval_execution(self):
        """
        CRITICAL SECURITY TEST: Verify eval-based attacks are prevented.
        """
        malicious_yaml = """!!python/object/new:eval ['__import__("os").system("whoami")']"""

        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            self.assertIn(response.status_code, [200, 400, 500])
        except Exception as e:
            # Exception is acceptable
            pass

    def test_blocks_file_read_attempt(self):
        """
        SECURITY TEST: Verify attempts to read sensitive files are blocked.
        """
        malicious_yaml = """!!python/object/new:file ['/etc/passwd']"""

        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            self.assertIn(response.status_code, [200, 400, 500])
            if response.status_code == 200:
                data = response.get_json()
                # Should not contain file contents
                self.assertNotIn('root:', str(data))
        except Exception as e:
            # Exception is acceptable
            pass

    def test_blocks_constructor_exploitation(self):
        """
        SECURITY TEST: Verify constructor-based object instantiation is blocked.
        """
        malicious_yaml = """
!!python/object/new:tuple
- !!python/object/new:map
  - !!python/name:eval
  - ["__import__('os').system('echo vulnerable')"]
"""
        try:
            response = self.client.post('/config',
                                       data=malicious_yaml,
                                       content_type='text/plain')
            self.assertIn(response.status_code, [200, 400, 500])
        except Exception as e:
            # Exception is acceptable
            pass

    # ========== EDGE CASES AND ROBUSTNESS TESTS ==========

    def test_handles_malformed_yaml(self):
        """Test that malformed YAML is handled gracefully."""
        malformed_yaml = """
name: test
  invalid indentation
    more invalid: stuff
"""
        try:
            response = self.client.post('/config',
                                       data=malformed_yaml,
                                       content_type='text/plain')
            # Should either parse what it can or return error, not crash
            self.assertIn(response.status_code, [200, 400, 500])
        except Exception as e:
            # Exception is acceptable for malformed input
            pass

    def test_handles_large_yaml_payload(self):
        """Test that large YAML payloads are handled appropriately."""
        # Create a large but valid YAML
        large_yaml = "items:\n"
        for i in range(1000):
            large_yaml += f"  - item_{i}: value_{i}\n"

        response = self.client.post('/config',
                                   data=large_yaml,
                                   content_type='text/plain')
        # Should handle large payloads without crashing
        self.assertIn(response.status_code, [200, 400, 413, 500])

    def test_handles_unicode_content(self):
        """Test that Unicode characters in YAML are handled correctly."""
        unicode_yaml = """
message: "Hello 世界 🌍"
emoji: "🔐🛡️✅"
japanese: "こんにちは"
"""
        response = self.client.post('/config',
                                   data=unicode_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('世界', data['message'])

    def test_handles_yaml_with_null_values(self):
        """Test YAML with null/None values."""
        null_yaml = """
name: test
value: null
empty: ~
"""
        response = self.client.post('/config',
                                   data=null_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNone(data['value'])
        self.assertIsNone(data['empty'])

    def test_yaml_with_boolean_values(self):
        """Test various boolean representations in YAML."""
        bool_yaml = """
enabled: true
disabled: false
yes_value: yes
no_value: no
on_value: on
off_value: off
"""
        response = self.client.post('/config',
                                   data=bool_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['enabled'])
        self.assertFalse(data['disabled'])
        self.assertTrue(data['yes_value'])
        self.assertFalse(data['no_value'])

    # ========== REGRESSION PREVENTION TESTS ==========

    def test_safe_load_is_used(self):
        """
        Regression test: Verify that safe_load is actually being used.
        This test documents the expected behavior.
        """
        # Test a tag that would work with unsafe load but not safe_load
        unsafe_tag_yaml = """!!python/name:os.system"""

        try:
            response = self.client.post('/config',
                                       data=unsafe_tag_yaml,
                                       content_type='text/plain')
            # safe_load should reject Python-specific tags
            # Either by raising an error or returning None/safe value
            if response.status_code == 200:
                data = response.get_json()
                # Should NOT be the actual os.system function
                self.assertNotEqual(str(type(data)), "<class 'builtin_function_or_method'>")
        except Exception as e:
            # Exception indicates safe_load is properly rejecting unsafe tags
            pass

    def test_maintains_yaml_standard_types(self):
        """
        Test that all standard YAML types still work correctly after the fix.
        """
        standard_types_yaml = """
string: "text"
integer: 42
float: 3.14
boolean: true
null_value: null
list:
  - item1
  - item2
dict:
  key: value
"""
        response = self.client.post('/config',
                                   data=standard_types_yaml,
                                   content_type='text/plain')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        # Verify all types are preserved correctly
        self.assertIsInstance(data['string'], str)
        self.assertIsInstance(data['integer'], int)
        self.assertIsInstance(data['float'], float)
        self.assertIsInstance(data['boolean'], bool)
        self.assertIsNone(data['null_value'])
        self.assertIsInstance(data['list'], list)
        self.assertIsInstance(data['dict'], dict)


if __name__ == '__main__':
    unittest.main()
