"""
Comprehensive test suite for user_data.py XSS vulnerability remediation.

Tests validate that the XSS vulnerability has been properly fixed and that
the application correctly sanitizes user data before returning it in responses.
"""
import pytest
import sys
import os

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.user_data import app, users
from markupsafe import escape


@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestXSSVulnerabilityRemediation:
    """Tests for XSS vulnerability fix in get_user endpoint."""

    def test_normal_user_data_returned(self, client):
        """Test that normal user data is returned correctly."""
        response = client.get('/user/1')
        assert response.status_code == 200
        data = response.get_json()

        # Verify user data is present
        assert 'name' in data
        assert 'email' in data
        assert 'ssn' in data
        assert 'role' in data

        # Verify specific values for user 1
        assert data['name'] == 'Alice'
        assert data['email'] == 'alice@example.com'
        assert data['role'] == 'user'

    def test_xss_attack_with_script_tag_is_sanitized(self, client):
        """Test that XSS attempts with <script> tags are properly escaped."""
        # Inject malicious user data
        original_users = users.copy()
        users['999'] = {
            "name": "<script>alert('XSS')</script>",
            "email": "hacker@evil.com",
            "ssn": "000-00-0000",
            "role": "user"
        }

        response = client.get('/user/999')
        assert response.status_code == 200
        data = response.get_json()

        # Verify the script tag is escaped
        assert data['name'] == escape("<script>alert('XSS')</script>")
        # The escaped version should not contain raw script tags
        assert '<script>' not in data['name']
        assert '&lt;script&gt;' in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_xss_attack_with_img_onerror_is_sanitized(self, client):
        """Test that XSS attempts with <img onerror> are properly escaped."""
        original_users = users.copy()
        users['888'] = {
            "name": "<img src=x onerror=alert('XSS')>",
            "email": "hacker@evil.com",
            "ssn": "000-00-0000",
            "role": "user"
        }

        response = client.get('/user/888')
        assert response.status_code == 200
        data = response.get_json()

        # Verify the img tag is escaped
        assert data['name'] == escape("<img src=x onerror=alert('XSS')>")
        assert '<img' not in data['name']
        assert '&lt;img' in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_xss_attack_with_event_handler_is_sanitized(self, client):
        """Test that XSS attempts with event handlers are properly escaped."""
        original_users = users.copy()
        users['777'] = {
            "name": "<div onload=alert('XSS')>Click me</div>",
            "email": "hacker@evil.com",
            "ssn": "000-00-0000",
            "role": "user"
        }

        response = client.get('/user/777')
        assert response.status_code == 200
        data = response.get_json()

        # Verify the div tag with event handler is escaped
        assert data['name'] == escape("<div onload=alert('XSS')>Click me</div>")
        assert 'onload=' not in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_xss_attack_with_javascript_protocol_is_sanitized(self, client):
        """Test that XSS attempts with javascript: protocol are properly escaped."""
        original_users = users.copy()
        users['666'] = {
            "name": "<a href='javascript:alert(1)'>Click</a>",
            "email": "hacker@evil.com",
            "ssn": "000-00-0000",
            "role": "user"
        }

        response = client.get('/user/666')
        assert response.status_code == 200
        data = response.get_json()

        # Verify the anchor tag with javascript protocol is escaped
        assert data['name'] == escape("<a href='javascript:alert(1)'>Click</a>")
        assert 'javascript:' not in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_xss_attack_multiple_fields_are_sanitized(self, client):
        """Test that XSS attempts in multiple fields are all sanitized."""
        original_users = users.copy()
        users['555'] = {
            "name": "<script>alert('name')</script>",
            "email": "<script>alert('email')</script>@evil.com",
            "ssn": "<b>000-00-0000</b>",
            "role": "<i>admin</i>"
        }

        response = client.get('/user/555')
        assert response.status_code == 200
        data = response.get_json()

        # Verify all fields are escaped
        assert '<script>' not in data['name']
        assert '<script>' not in data['email']
        assert '<b>' not in data['ssn']
        assert '<i>' not in data['role']

        assert '&lt;script&gt;' in data['name']
        assert '&lt;script&gt;' in data['email']
        assert '&lt;b&gt;' in data['ssn']
        assert '&lt;i&gt;' in data['role']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_special_characters_are_properly_escaped(self, client):
        """Test that special HTML characters are properly escaped."""
        original_users = users.copy()
        users['444'] = {
            "name": "John & Jane <Company>",
            "email": "test@example.com",
            "ssn": "111-11-1111",
            "role": "user"
        }

        response = client.get('/user/444')
        assert response.status_code == 200
        data = response.get_json()

        # Verify special characters are escaped
        assert data['name'] == escape("John & Jane <Company>")
        assert '&amp;' in data['name']
        assert '&lt;' in data['name']
        assert '&gt;' in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_user_not_found_returns_404(self, client):
        """Test that non-existent user returns 404."""
        response = client.get('/user/9999')
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data
        assert data['error'] == 'User not found'

    def test_security_headers_are_set(self, client):
        """Test that proper security headers are set in the response."""
        response = client.get('/user/1')
        assert response.status_code == 200

        # Verify Content-Type header
        assert response.headers.get('Content-Type') == 'application/json'

        # Verify X-Content-Type-Options header (prevents MIME sniffing)
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_response_is_valid_json(self, client):
        """Test that the response is valid JSON format."""
        response = client.get('/user/1')
        assert response.status_code == 200

        # get_json() will raise an exception if invalid JSON
        data = response.get_json()
        assert data is not None
        assert isinstance(data, dict)

    def test_original_data_structure_preserved(self, client):
        """Test that the data structure is preserved after sanitization."""
        response = client.get('/user/2')
        assert response.status_code == 200
        data = response.get_json()

        # Verify all expected keys are present
        expected_keys = {'name', 'email', 'ssn', 'role'}
        assert set(data.keys()) == expected_keys

        # Verify data types are preserved
        assert isinstance(data['name'], str)
        assert isinstance(data['email'], str)
        assert isinstance(data['ssn'], str)
        assert isinstance(data['role'], str)


class TestRegressionPrevention:
    """Tests to prevent regression of the XSS vulnerability."""

    def test_no_unescaped_html_in_any_user_field(self, client):
        """
        Regression test: Ensure all user fields are always escaped.
        This test will fail if the sanitization is removed or bypassed.
        """
        original_users = users.copy()

        # Test various XSS payloads
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ]

        for idx, payload in enumerate(xss_payloads):
            user_id = f"xss_{idx}"
            users[user_id] = {
                "name": payload,
                "email": "test@example.com",
                "ssn": "000-00-0000",
                "role": "user"
            }

            response = client.get(f'/user/{user_id}')
            assert response.status_code == 200
            data = response.get_json()

            # Critical: raw HTML tags should never appear in the response
            assert '<script' not in data['name'].lower()
            assert '<img' not in data['name'].lower()
            assert '<svg' not in data['name'].lower()
            assert '<iframe' not in data['name'].lower()
            assert '<body' not in data['name'].lower()
            assert 'javascript:' not in data['name'].lower()

            # Verify escaping is applied
            assert '&lt;' in data['name'] or '&amp;' in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_edge_case_empty_string_values(self, client):
        """Test handling of empty string values."""
        original_users = users.copy()
        users['empty'] = {
            "name": "",
            "email": "",
            "ssn": "",
            "role": ""
        }

        response = client.get('/user/empty')
        assert response.status_code == 200
        data = response.get_json()

        # Empty strings should remain empty
        assert data['name'] == ''
        assert data['email'] == ''

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_edge_case_unicode_characters(self, client):
        """Test handling of unicode characters."""
        original_users = users.copy()
        users['unicode'] = {
            "name": "José García 日本語 🎉",
            "email": "jose@example.com",
            "ssn": "111-11-1111",
            "role": "user"
        }

        response = client.get('/user/unicode')
        assert response.status_code == 200
        data = response.get_json()

        # Unicode should be preserved
        assert 'José' in data['name'] or 'Jos' in data['name']  # May be encoded

        # Cleanup
        users.clear()
        users.update(original_users)

    def test_edge_case_very_long_malicious_input(self, client):
        """Test handling of very long XSS payloads."""
        original_users = users.copy()

        # Create a long malicious payload
        long_payload = "<script>alert('XSS')</script>" * 100

        users['long'] = {
            "name": long_payload,
            "email": "test@example.com",
            "ssn": "000-00-0000",
            "role": "user"
        }

        response = client.get('/user/long')
        assert response.status_code == 200
        data = response.get_json()

        # Verify the entire payload is escaped
        assert '<script>' not in data['name']
        assert '&lt;script&gt;' in data['name']

        # Cleanup
        users.clear()
        users.update(original_users)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
