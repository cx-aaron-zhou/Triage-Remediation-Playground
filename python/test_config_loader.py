"""
Test suite for config_loader.py - CVE-2020-14343 remediation validation

This test suite validates that:
1. The PyYAML upgrade to 6.0.3 is compatible with the application
2. yaml.safe_load() correctly processes legitimate YAML configurations
3. Malicious YAML payloads with !!python/object tags are rejected
4. The application maintains backward compatibility for valid use cases
"""

import unittest
import yaml
from utils.config_loader import app


class TestConfigLoaderSecurity(unittest.TestCase):
    """Test security aspects of the config loader after CVE-2020-14343 fix"""

    def setUp(self):
        """Set up test client for Flask application"""
        self.app = app
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True

    def test_safe_yaml_simple_dict(self):
        """Test that legitimate simple YAML dict is processed correctly"""
        yaml_data = """
        name: test_config
        version: 1.0
        enabled: true
        """
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data['name'], 'test_config')
        self.assertEqual(json_data['version'], 1.0)
        self.assertTrue(json_data['enabled'])

    def test_safe_yaml_nested_structure(self):
        """Test that nested YAML structures are handled correctly"""
        yaml_data = """
        database:
          host: localhost
          port: 5432
          credentials:
            username: admin
            password: secret
        features:
          - feature1
          - feature2
          - feature3
        """
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data['database']['host'], 'localhost')
        self.assertEqual(json_data['database']['port'], 5432)
        self.assertIsInstance(json_data['features'], list)
        self.assertEqual(len(json_data['features']), 3)

    def test_safe_yaml_with_numbers_and_booleans(self):
        """Test various data types are preserved correctly"""
        yaml_data = """
        integer: 42
        float: 3.14
        boolean_true: true
        boolean_false: false
        null_value: null
        string: "hello world"
        """
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data['integer'], 42)
        self.assertAlmostEqual(json_data['float'], 3.14)
        self.assertTrue(json_data['boolean_true'])
        self.assertFalse(json_data['boolean_false'])
        self.assertIsNone(json_data['null_value'])
        self.assertEqual(json_data['string'], "hello world")

    def test_blocks_arbitrary_python_object_execution(self):
        """
        Test that malicious YAML with !!python/object tags is rejected
        This validates the fix for CVE-2020-14343
        """
        # Malicious payload attempting to execute os.system
        malicious_yaml = "!!python/object/apply:os.system ['id']"

        # With yaml.safe_load(), this should raise a ConstructorError
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load(malicious_yaml)

    def test_blocks_python_object_instantiation(self):
        """Test that arbitrary Python object instantiation is blocked"""
        # Attempt to instantiate a Python object
        malicious_yaml = """
        !!python/object:__main__.SomeClass
        attribute: value
        """

        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load(malicious_yaml)

    def test_blocks_eval_and_exec_attempts(self):
        """Test that eval/exec injection attempts via YAML are blocked"""
        malicious_payloads = [
            "!!python/object/apply:eval ['__import__(\"os\").system(\"id\")']",
            "!!python/object/apply:exec ['import os; os.system(\"id\")']",
            "!!python/object/new:os.system [id]"
        ]

        for payload in malicious_payloads:
            with self.assertRaises(yaml.constructor.ConstructorError):
                yaml.safe_load(payload)

    def test_empty_yaml_document(self):
        """Test handling of empty YAML document"""
        yaml_data = ""
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIsNone(json_data)

    def test_yaml_with_comments(self):
        """Test that YAML comments are handled correctly"""
        yaml_data = """
        # This is a comment
        name: production  # Environment name
        # Another comment
        debug: false
        """
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data['name'], 'production')
        self.assertFalse(json_data['debug'])

    def test_yaml_list_structure(self):
        """Test that YAML lists are processed correctly"""
        yaml_data = """
        - item1
        - item2
        - item3
        """
        response = self.client.post('/config', data=yaml_data)
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIsInstance(json_data, list)
        self.assertEqual(len(json_data), 3)
        self.assertEqual(json_data[0], 'item1')


class TestPyYAMLUpgradeCompatibility(unittest.TestCase):
    """Test that PyYAML 6.0.3 upgrade maintains expected behavior"""

    def test_pyyaml_version(self):
        """Verify PyYAML version is 6.0.3 or higher"""
        # PyYAML 6.0.3 should be installed
        import yaml
        version = yaml.__version__
        major, minor, patch = map(int, version.split('.'))

        # Assert we're on version 6.0.3 or higher
        self.assertGreaterEqual(major, 6)
        if major == 6 and minor == 0:
            self.assertGreaterEqual(patch, 3)

    def test_safe_load_is_secure(self):
        """Verify yaml.safe_load is being used and is secure"""
        from utils.config_loader import load_config
        import inspect

        # Get the source code of the load_config function
        source = inspect.getsource(load_config)

        # Verify safe_load is used instead of unsafe load
        self.assertIn('yaml.safe_load', source)
        self.assertNotIn('yaml.load(', source)
        self.assertNotIn('yaml.unsafe_load', source)
        self.assertNotIn('yaml.full_load', source)

    def test_safe_load_allows_safe_constructors_only(self):
        """Test that yaml.safe_load only allows safe constructors"""
        safe_yaml = """
        string: value
        number: 123
        list: [1, 2, 3]
        dict:
          nested: true
        """

        # This should work fine
        result = yaml.safe_load(safe_yaml)
        self.assertIsInstance(result, dict)
        self.assertEqual(result['string'], 'value')


if __name__ == '__main__':
    unittest.main()
