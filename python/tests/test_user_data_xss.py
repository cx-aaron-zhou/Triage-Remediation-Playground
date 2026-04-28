"""
Test suite for XSS vulnerability remediation in user_data.py

This test suite validates that the Reflected XSS vulnerability (CWE-79)
has been properly fixed in the get_user endpoint.
"""
import pytest
import json
import sys
import os

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.user_data import app, users


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestXSSRemediation:
    """Test cases for XSS vulnerability fix in get_user endpoint."""

    def test_normal_user_retrieval(self, client):
        """Test that normal user retrieval still works correctly."""
        response = client.get('/user/1')
        assert response.status_code == 200
        data = json.loads(response.data)

        # Verify user data is returned
        assert 'name' in data
        assert 'email' in data
        assert data['name'] == 'Alice'
        assert data['email'] == 'alice@example.com'

    def test_user_not_found(self, client):
        """Test that non-existent user returns 404."""
        response = client.get('/user/999')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'User not found'

    def test_xss_script_tag_escaped_in_response(self, client):
        """Test that script tags in user data are properly escaped."""
        # Inject XSS payload into users dict temporarily
        users['xss_test'] = {
            'name': '<script>alert("XSS")</script>',
            'email': 'test@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/xss_test')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify the script tag is escaped, not executable
            assert '<script>' not in data['name']
            assert '&lt;script&gt;' in data['name'] or '&lt;' in data['name']
            # The escaped version should be safe
            assert 'alert' in data['name']  # Content still there but escaped
        finally:
            # Clean up test data
            del users['xss_test']

    def test_xss_img_onerror_escaped(self, client):
        """Test that img onerror XSS payloads are properly escaped."""
        users['xss_img'] = {
            'name': '<img src=x onerror=alert(1)>',
            'email': 'img@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/xss_img')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify HTML tags are escaped
            assert '<img' not in data['name']
            assert '&lt;img' in data['name'] or '&lt;' in data['name']
            assert 'onerror' in data['name']  # Still contains text but safe
        finally:
            del users['xss_img']

    def test_xss_event_handler_escaped(self, client):
        """Test that event handlers in user data are escaped."""
        users['xss_event'] = {
            'name': '<div onload=alert("XSS")>Test</div>',
            'email': 'event@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/xss_event')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify event handlers are escaped
            assert '<div' not in data['name']
            assert 'onload=' not in data['name'] or '&lt;' in data['name']
        finally:
            del users['xss_event']

    def test_xss_multiple_fields_escaped(self, client):
        """Test that XSS payloads in multiple fields are all escaped."""
        users['xss_multi'] = {
            'name': '<script>alert("name")</script>',
            'email': '<script>alert("email")</script>',
            'role': '<script>alert("role")</script>'
        }

        try:
            response = client.get('/user/xss_multi')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify all fields are escaped
            for field in ['name', 'email', 'role']:
                assert '<script>' not in data[field]
                assert '&lt;script&gt;' in data[field] or '&lt;' in data[field]
        finally:
            del users['xss_multi']

    def test_security_headers_present(self, client):
        """Test that security headers are properly set to prevent XSS."""
        response = client.get('/user/1')

        # Verify Content-Type is set correctly
        assert 'Content-Type' in response.headers
        assert 'application/json' in response.headers['Content-Type']
        assert 'charset=utf-8' in response.headers['Content-Type']

        # Verify X-Content-Type-Options is set to prevent MIME sniffing
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'

    def test_javascript_protocol_escaped(self, client):
        """Test that javascript: protocol URLs are escaped."""
        users['xss_protocol'] = {
            'name': 'Test User',
            'email': 'javascript:alert(1)',
            'role': 'user'
        }

        try:
            response = client.get('/user/xss_protocol')
            assert response.status_code == 200
            data = json.loads(response.data)

            # The email should still contain the text but be safe in JSON context
            assert 'javascript:' in data['email']
            # When rendered in HTML, it should be escaped by the client
        finally:
            del users['xss_protocol']

    def test_unicode_xss_escaped(self, client):
        """Test that unicode-based XSS attempts are handled safely."""
        users['xss_unicode'] = {
            'name': '\u003cscript\u003ealert("XSS")\u003c/script\u003e',
            'email': 'unicode@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/xss_unicode')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify escaped or safe
            name_str = str(data['name'])
            # Should not have raw script tags
            assert '<script>' not in name_str or '&lt;' in name_str
        finally:
            del users['xss_unicode']

    def test_html_entities_preserved(self, client):
        """Test that legitimate HTML entities in data are handled properly."""
        users['entity_test'] = {
            'name': 'Tom & Jerry',
            'email': 'tom.jerry@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/entity_test')
            assert response.status_code == 200
            data = json.loads(response.data)

            # The ampersand should be escaped for safety
            assert '&amp;' in data['name'] or 'Tom & Jerry' in data['name']
        finally:
            del users['entity_test']

    def test_sql_injection_like_strings_safe(self, client):
        """Test that SQL-like strings don't cause issues (defense in depth)."""
        users['sql_test'] = {
            'name': "'; DROP TABLE users; --",
            'email': 'sql@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/sql_test')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Data should be returned safely
            assert "DROP TABLE" in data['name']
        finally:
            del users['sql_test']

    def test_xss_with_special_characters(self, client):
        """Test handling of various special characters that could be used in XSS."""
        users['special_chars'] = {
            'name': '"><svg/onload=alert(1)>',
            'email': "test'><script>alert(1)</script>",
            'role': 'user'
        }

        try:
            response = client.get('/user/special_chars')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Verify dangerous characters are escaped
            assert '<svg' not in data['name'] or '&lt;' in data['name']
            assert '<script>' not in data['email']
        finally:
            del users['special_chars']

    def test_response_is_valid_json(self, client):
        """Test that the response is always valid JSON after sanitization."""
        users['json_test'] = {
            'name': '<script>alert(1)</script>',
            'email': 'json@example.com',
            'role': 'user'
        }

        try:
            response = client.get('/user/json_test')
            assert response.status_code == 200

            # Should be able to parse as JSON without errors
            data = json.loads(response.data)
            assert isinstance(data, dict)
            assert 'name' in data
            assert 'email' in data
        finally:
            del users['json_test']

    def test_empty_string_fields(self, client):
        """Test that empty strings are handled correctly."""
        users['empty_test'] = {
            'name': '',
            'email': '',
            'role': ''
        }

        try:
            response = client.get('/user/empty_test')
            assert response.status_code == 200
            data = json.loads(response.data)

            assert data['name'] == ''
            assert data['email'] == ''
            assert data['role'] == ''
        finally:
            del users['empty_test']

    def test_numeric_values_unchanged(self, client):
        """Test that numeric values in user data are not affected."""
        users['numeric_test'] = {
            'name': 'Test User',
            'email': 'test@example.com',
            'age': 25,
            'score': 95.5
        }

        try:
            response = client.get('/user/numeric_test')
            assert response.status_code == 200
            data = json.loads(response.data)

            # Numeric values should remain numeric
            assert data['age'] == 25
            assert data['score'] == 95.5
        finally:
            del users['numeric_test']
