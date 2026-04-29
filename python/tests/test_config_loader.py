"""
Tests for config_loader.py
Validates that the YAML deserialization vulnerability has been fixed.
"""
import pytest
import json
from python.utils.config_loader import app


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestConfigLoaderSecurity:
    """Security tests for the config loader endpoint."""

    def test_safe_yaml_loading(self, client):
        """Test that safe YAML configurations are loaded correctly."""
        safe_yaml = """
database:
  host: localhost
  port: 5432
  name: mydb
settings:
  debug: false
  timeout: 30
"""
        response = client.post('/config', data=safe_yaml.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['database']['host'] == 'localhost'
        assert data['database']['port'] == 5432
        assert data['settings']['debug'] is False
        assert data['settings']['timeout'] == 30

    def test_blocks_python_object_instantiation(self, client):
        """Test that malicious YAML with Python object tags is rejected."""
        # This payload would execute 'id' command with unsafe yaml.load()
        malicious_yaml = "!!python/object/apply:os.system ['id']"
        response = client.post('/config', data=malicious_yaml.encode('utf-8'))
        # safe_load should raise an error for Python object tags
        # The response will be a 500 error instead of executing code
        assert response.status_code == 500

    def test_blocks_arbitrary_python_code_execution(self, client):
        """Test that arbitrary Python code execution is prevented."""
        # Attempt to create a malicious object that would execute code
        malicious_yaml = """
!!python/object/new:os.system
args: ['echo hacked']
"""
        response = client.post('/config', data=malicious_yaml.encode('utf-8'))
        # safe_load should raise an error, resulting in 500 status
        assert response.status_code == 500

    def test_blocks_arbitrary_object_instantiation(self, client):
        """Test that arbitrary Python object instantiation is blocked."""
        # Attempt to instantiate arbitrary Python objects
        malicious_yaml = "!!python/object/apply:subprocess.Popen [['ls', '-la']]"
        response = client.post('/config', data=malicious_yaml.encode('utf-8'))
        # safe_load should raise an error
        assert response.status_code == 500


class TestConfigLoaderFunctionality:
    """Functional tests for the config loader endpoint."""

    def test_simple_string_config(self, client):
        """Test loading a simple string configuration."""
        yaml_data = "message: Hello, World!"
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Hello, World!'

    def test_nested_yaml_structure(self, client):
        """Test loading nested YAML structures."""
        yaml_data = """
api:
  endpoints:
    - name: users
      path: /api/users
    - name: posts
      path: /api/posts
  version: v1
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['api']['version'] == 'v1'
        assert len(data['api']['endpoints']) == 2
        assert data['api']['endpoints'][0]['name'] == 'users'

    def test_yaml_with_numbers(self, client):
        """Test loading YAML with various number types."""
        yaml_data = """
integers: 42
floats: 3.14
negative: -100
scientific: 1.23e-4
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['integers'] == 42
        assert data['floats'] == 3.14
        assert data['negative'] == -100
        assert abs(data['scientific'] - 1.23e-4) < 1e-10

    def test_yaml_with_booleans(self, client):
        """Test loading YAML with boolean values."""
        yaml_data = """
enabled: true
disabled: false
yes_value: yes
no_value: no
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['enabled'] is True
        assert data['disabled'] is False
        assert data['yes_value'] is True
        assert data['no_value'] is False

    def test_yaml_with_null_values(self, client):
        """Test loading YAML with null values."""
        yaml_data = """
value1: null
value2: ~
value3:
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['value1'] is None
        assert data['value2'] is None
        assert data['value3'] is None

    def test_yaml_with_lists(self, client):
        """Test loading YAML with list structures."""
        yaml_data = """
fruits:
  - apple
  - banana
  - orange
numbers: [1, 2, 3, 4, 5]
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['fruits'] == ['apple', 'banana', 'orange']
        assert data['numbers'] == [1, 2, 3, 4, 5]

    def test_empty_yaml(self, client):
        """Test loading empty YAML."""
        yaml_data = ""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data is None

    def test_yaml_with_special_characters(self, client):
        """Test loading YAML with special characters in strings."""
        yaml_data = """
special: "String with: colon, @symbol, #hash"
quoted: 'Single quoted string'
multiline: |
  This is a
  multiline string
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert 'colon' in data['special']
        assert data['quoted'] == 'Single quoted string'
        assert 'multiline' in data['multiline']


class TestConfigLoaderEdgeCases:
    """Edge case tests for the config loader endpoint."""

    def test_malformed_yaml(self, client):
        """Test that malformed YAML is rejected gracefully."""
        malformed_yaml = """
key: value
  invalid indentation
key2: value2
"""
        response = client.post('/config', data=malformed_yaml.encode('utf-8'))
        # Should return an error due to invalid YAML syntax
        assert response.status_code == 500

    def test_yaml_with_unicode(self, client):
        """Test loading YAML with Unicode characters."""
        yaml_data = """
message: "Hello 世界 🌍"
emoji: "🚀 🎉 ✨"
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert '世界' in data['message']
        assert '🚀' in data['emoji']

    def test_deeply_nested_structure(self, client):
        """Test loading deeply nested YAML structures."""
        yaml_data = """
level1:
  level2:
    level3:
      level4:
        level5:
          value: "deep"
"""
        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert data['level1']['level2']['level3']['level4']['level5']['value'] == 'deep'

    def test_large_yaml_structure(self, client):
        """Test loading a large YAML structure."""
        # Create a moderately large YAML with many items
        items = []
        for i in range(100):
            items.append(f"  - id: {i}\n    name: item{i}\n    value: {i * 10}")
        yaml_data = "items:\n" + "\n".join(items)

        response = client.post('/config', data=yaml_data.encode('utf-8'))
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['items']) == 100
        assert data['items'][0]['id'] == 0
        assert data['items'][99]['id'] == 99
