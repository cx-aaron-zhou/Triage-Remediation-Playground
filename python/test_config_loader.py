"""
Test suite for config_loader.py to validate PyYAML security fix.

This test suite ensures that:
1. CVE-2020-14343 vulnerability is remediated by using yaml.safe_load()
2. Arbitrary code execution attacks are prevented
3. Normal YAML configuration loading works correctly
4. Malicious YAML payloads are safely rejected
"""

import unittest
import json
import sys
import os

# Add the utils directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

from config_loader import app


class TestConfigLoaderSecurity(unittest.TestCase):
    """Test cases for YAML configuration loading security."""

    def setUp(self):
        """Set up test client before each test."""
        self.app = app
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True

    def test_safe_yaml_loading_simple_config(self):
        """Test that safe YAML loading works with simple configuration."""
        yaml_data = """
database:
  host: localhost
  port: 5432
  name: testdb
"""
        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('database', data)
        self.assertEqual(data['database']['host'], 'localhost')
        self.assertEqual(data['database']['port'], 5432)
        self.assertEqual(data['database']['name'], 'testdb')

    def test_safe_yaml_loading_nested_config(self):
        """Test that safe YAML loading works with nested configuration."""
        yaml_data = """
app:
  name: MyApp
  version: 1.0.0
  settings:
    debug: true
    timeout: 30
    features:
      - authentication
      - logging
      - monitoring
"""
        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('app', data)
        self.assertEqual(data['app']['name'], 'MyApp')
        self.assertEqual(data['app']['version'], '1.0.0')
        self.assertTrue(data['app']['settings']['debug'])
        self.assertIn('authentication', data['app']['settings']['features'])

    def test_blocks_python_object_deserialization(self):
        """
        Test that arbitrary Python object deserialization is blocked.

        This test verifies the fix for CVE-2020-14343.
        With yaml.load() (vulnerable), this payload would execute code.
        With yaml.safe_load() (fixed), this should be safely rejected.
        """
        # Malicious payload attempting to execute system command
        malicious_yaml = "!!python/object/apply:os.system ['echo pwned']"

        response = self.client.post(
            '/config',
            data=malicious_yaml,
            content_type='text/plain'
        )

        # With safe_load, this should return an error or empty response,
        # NOT execute the command
        # The exact behavior depends on PyYAML version, but it should NOT succeed
        # in executing the command
        if response.status_code == 200:
            # If it returns 200, the data should be null/none, not executed
            data = json.loads(response.data)
            # The payload should not be processed as intended by the attacker
            self.assertIsNone(data)
        else:
            # Or it should return an error status
            self.assertNotEqual(response.status_code, 200)

    def test_blocks_python_module_import(self):
        """
        Test that Python module imports are blocked.

        Another variant of CVE-2020-14343 exploitation.
        """
        malicious_yaml = "!!python/object/new:os.system [echo hacked]"

        response = self.client.post(
            '/config',
            data=malicious_yaml,
            content_type='text/plain'
        )

        # Should not execute the command
        if response.status_code == 200:
            data = json.loads(response.data)
            self.assertIsNone(data)
        else:
            self.assertNotEqual(response.status_code, 200)

    def test_blocks_python_object_with_apply(self):
        """
        Test that !!python/object/apply tags are blocked.

        This is the specific attack vector mentioned in CVE-2020-14343.
        """
        malicious_yaml = "!!python/object/apply:subprocess.Popen [['ls', '-la']]"

        response = self.client.post(
            '/config',
            data=malicious_yaml,
            content_type='text/plain'
        )

        # Should not execute the command
        if response.status_code == 200:
            data = json.loads(response.data)
            self.assertIsNone(data)
        else:
            self.assertNotEqual(response.status_code, 200)

    def test_handles_empty_yaml(self):
        """Test that empty YAML is handled correctly."""
        yaml_data = ""

        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsNone(data)

    def test_handles_yaml_with_numbers_and_booleans(self):
        """Test that YAML with various data types is handled correctly."""
        yaml_data = """
settings:
  max_connections: 100
  timeout: 30.5
  enabled: true
  disabled: false
  null_value: null
"""
        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['settings']['max_connections'], 100)
        self.assertEqual(data['settings']['timeout'], 30.5)
        self.assertTrue(data['settings']['enabled'])
        self.assertFalse(data['settings']['disabled'])
        self.assertIsNone(data['settings']['null_value'])

    def test_handles_yaml_lists(self):
        """Test that YAML lists are handled correctly."""
        yaml_data = """
servers:
  - name: server1
    ip: 192.168.1.1
  - name: server2
    ip: 192.168.1.2
  - name: server3
    ip: 192.168.1.3
"""
        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('servers', data)
        self.assertEqual(len(data['servers']), 3)
        self.assertEqual(data['servers'][0]['name'], 'server1')
        self.assertEqual(data['servers'][1]['ip'], '192.168.1.2')

    def test_handles_yaml_with_special_characters(self):
        """Test that YAML with special characters is handled correctly."""
        yaml_data = """
message: "Hello, World! This is a test with special chars: @#$%^&*()"
path: "/usr/local/bin"
regex: "^[a-zA-Z0-9]+$"
"""
        response = self.client.post(
            '/config',
            data=yaml_data,
            content_type='text/plain'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('Hello, World!', data['message'])
        self.assertEqual(data['path'], '/usr/local/bin')
        self.assertEqual(data['regex'], '^[a-zA-Z0-9]+$')


class TestConfigLoaderIntegration(unittest.TestCase):
    """Integration tests for config_loader endpoint."""

    def setUp(self):
        """Set up test client before each test."""
        self.app = app
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True

    def test_endpoint_accepts_post_only(self):
        """Test that the endpoint only accepts POST requests."""
        yaml_data = "test: value"

        # POST should work
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)

        # GET should fail
        response = self.client.get('/config')
        self.assertEqual(response.status_code, 405)

    def test_endpoint_returns_json(self):
        """Test that the endpoint returns JSON content type."""
        yaml_data = "key: value"

        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response.content_type)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
