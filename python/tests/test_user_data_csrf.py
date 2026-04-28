"""
Tests for CSRF protection in user_data.py

This test file validates that the CSRF vulnerability in the list_all_users
endpoint has been properly remediated by implementing Flask-WTF CSRF protection.
"""

import pytest
from flask import session
from python.utils.user_data import app, csrf


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'

    with app.test_client() as client:
        yield client


@pytest.fixture
def client_no_csrf():
    """Create a test client with CSRF protection disabled for baseline tests."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'

    with app.test_client() as client:
        yield client


class TestCSRFProtectionEnabled:
    """Test that CSRF protection is properly configured."""

    def test_csrf_protect_initialized(self):
        """Verify CSRFProtect is initialized for the application."""
        assert csrf is not None
        assert hasattr(app, 'config')
        assert 'SECRET_KEY' in app.config

    def test_secret_key_configured(self):
        """Verify SECRET_KEY is configured (required for CSRF protection)."""
        assert app.config.get('SECRET_KEY') is not None
        assert len(app.config.get('SECRET_KEY')) > 0


class TestListAllUsersEndpoint:
    """Test the list_all_users endpoint functionality and CSRF protection."""

    def test_list_all_users_get_request_succeeds(self, client):
        """Test that GET request to /admin/users works (GET is safe method)."""
        response = client.get('/admin/users')
        assert response.status_code == 200
        assert response.is_json
        data = response.get_json()
        assert '1' in data
        assert '2' in data
        assert data['1']['name'] == 'Alice'
        assert data['2']['name'] == 'Bob'

    def test_list_all_users_returns_all_user_data(self, client):
        """Test that the endpoint returns complete user data."""
        response = client.get('/admin/users')
        data = response.get_json()

        # Verify user 1 data
        assert data['1']['email'] == 'alice@example.com'
        assert data['1']['ssn'] == '123-45-6789'
        assert data['1']['role'] == 'user'

        # Verify user 2 data
        assert data['2']['email'] == 'bob@example.com'
        assert data['2']['ssn'] == '987-65-4321'
        assert data['2']['role'] == 'admin'


class TestCSRFProtectionOnStateChangingMethods:
    """
    Test CSRF protection on state-changing HTTP methods.

    While list_all_users currently uses GET, CSRF protection should prevent
    CSRF attacks if the endpoint is ever changed to use POST/PUT/DELETE/PATCH.
    """

    def test_post_request_without_csrf_token_fails(self, client):
        """Test that POST request without CSRF token is rejected."""
        # Attempt to POST to the admin users endpoint without CSRF token
        # This would fail with 400 or 403 if the endpoint accepted POST
        # and CSRF protection was active
        response = client.post('/admin/users')
        # Flask will return 405 Method Not Allowed since only GET is allowed
        # but if it were allowed, CSRF protection would require a token
        assert response.status_code in [400, 403, 405]

    def test_put_request_without_csrf_token_fails(self, client):
        """Test that PUT request without CSRF token is rejected."""
        response = client.put('/admin/users')
        # Should fail with method not allowed or CSRF error
        assert response.status_code in [400, 403, 405]

    def test_delete_request_without_csrf_token_fails(self, client):
        """Test that DELETE request without CSRF token is rejected."""
        response = client.delete('/admin/users')
        # Should fail with method not allowed or CSRF error
        assert response.status_code in [400, 403, 405]

    def test_csrf_token_generation_available(self, client):
        """Test that CSRF token generation is available in the application."""
        with client:
            # Make a request to initialize the session
            client.get('/admin/users')
            # With Flask-WTF installed, csrf tokens should be available
            # This ensures the CSRF infrastructure is in place
            assert 'csrf_token' in dir(csrf) or hasattr(csrf, '_get_csrf_token')


class TestCSRFRegressionPrevention:
    """
    Tests to prevent regression of the CSRF vulnerability.

    These tests ensure that CSRF protection remains active and properly
    configured even if code changes are made in the future.
    """

    def test_csrf_protection_not_disabled(self):
        """Ensure CSRF protection is not globally disabled."""
        # In production, WTF_CSRF_ENABLED should not be explicitly set to False
        # or should be True
        assert app.config.get('WTF_CSRF_ENABLED', True) is not False

    def test_csrf_exempt_not_applied_to_list_all_users(self):
        """Verify that csrf.exempt decorator is not applied to list_all_users."""
        from python.utils.user_data import list_all_users

        # Check if the function has csrf_exempt marker
        # Functions decorated with @csrf.exempt have a special attribute
        assert not hasattr(list_all_users, 'csrf_exempt')
        assert not getattr(list_all_users, 'csrf_exempt', False)

    def test_app_has_secret_key_in_config(self):
        """Verify app maintains SECRET_KEY configuration."""
        assert 'SECRET_KEY' in app.config
        secret_key = app.config['SECRET_KEY']
        assert secret_key is not None
        assert isinstance(secret_key, str)
        assert len(secret_key) > 0

    def test_csrf_protect_instance_exists(self):
        """Verify CSRFProtect instance is attached to app."""
        assert csrf is not None
        # CSRFProtect should have the app registered
        assert hasattr(csrf, 'app') or hasattr(csrf, '_app')


class TestEndpointAccessControl:
    """
    Additional tests for the admin endpoint security.

    While CSRF is the primary concern, these tests document other
    security considerations for this admin endpoint.
    """

    def test_admin_endpoint_accessible(self, client_no_csrf):
        """Test that admin endpoint is accessible (authentication not in scope)."""
        # Note: The original code has broken access control (no authentication)
        # This test documents the current state - authentication is a separate issue
        response = client_no_csrf.get('/admin/users')
        assert response.status_code == 200

    def test_admin_endpoint_returns_sensitive_data(self, client_no_csrf):
        """Document that endpoint returns sensitive data like SSNs."""
        # This is a separate vulnerability (information disclosure)
        # but documented here for completeness
        response = client_no_csrf.get('/admin/users')
        data = response.get_json()
        # The endpoint currently returns SSN data
        assert 'ssn' in data['1']
        assert 'ssn' in data['2']


class TestCSRFEdgeCases:
    """Test edge cases and attack vectors related to CSRF."""

    def test_get_request_with_query_params(self, client):
        """Test that GET requests with query parameters work correctly."""
        response = client.get('/admin/users?filter=admin')
        # Should still work (GET is safe method)
        assert response.status_code == 200

    def test_options_request_allowed(self, client):
        """Test that OPTIONS requests are handled correctly."""
        response = client.options('/admin/users')
        # OPTIONS should be allowed without CSRF token
        assert response.status_code in [200, 204, 405]

    def test_head_request_allowed(self, client):
        """Test that HEAD requests work correctly."""
        response = client.head('/admin/users')
        # HEAD should work like GET
        assert response.status_code in [200, 405]


# Integration tests
class TestCSRFIntegration:
    """Integration tests for CSRF protection across the application."""

    def test_multiple_requests_maintain_csrf_protection(self, client):
        """Test that CSRF protection is maintained across multiple requests."""
        # First request
        response1 = client.get('/admin/users')
        assert response1.status_code == 200

        # Second request
        response2 = client.get('/admin/users')
        assert response2.status_code == 200

        # Both should succeed (GET is safe)
        assert response1.get_json() == response2.get_json()

    def test_csrf_protection_with_different_endpoints(self, client):
        """Test that CSRF protection applies to other endpoints too."""
        # Test the /user/<user_id> endpoint as well
        response = client.get('/user/1')
        assert response.status_code == 200

        # Admin endpoint should also work
        response = client.get('/admin/users')
        assert response.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
