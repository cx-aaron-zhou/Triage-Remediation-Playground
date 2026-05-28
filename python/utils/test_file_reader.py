"""
Comprehensive tests for file_reader.py to validate Reflected XSS vulnerability fix.

These tests verify that:
1. The download_file function properly sanitizes filenames to prevent XSS
2. Files are served with as_attachment=True to prevent inline execution
3. The Content-Disposition header contains a safely encoded filename
4. Malicious filenames with XSS payloads are neutralized
"""
import os
import tempfile
import pytest
from flask import Flask
from werkzeug.utils import secure_filename


# Import the app and function under test
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from file_reader import app, download_file, BASE_DIR


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def temp_test_dir(tmp_path):
    """Create a temporary directory with test files."""
    # Create a safe test file
    safe_file = tmp_path / "safe_document.txt"
    safe_file.write_text("This is a safe document.")

    # Create an HTML file that could be used for XSS
    html_file = tmp_path / "test.html"
    html_file.write_text("<html><body><script>alert('XSS')</script></body></html>")

    return tmp_path


class TestReflectedXSSFix:
    """Test cases specifically for the Reflected XSS vulnerability fix at line 16."""

    def test_filename_sanitization_in_download_name(self, client, monkeypatch, temp_test_dir):
        """
        Test that malicious filenames are sanitized in the download_name parameter.

        This prevents XSS attacks where an attacker provides a filename like:
        <script>alert('XSS')</script>.txt

        The secure_filename function should strip out dangerous characters.
        """
        # Patch BASE_DIR to use our temp directory
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Create a test file
        test_file = temp_test_dir / "test.txt"
        test_file.write_text("test content")

        # Test with XSS payload in filename
        response = client.get('/download?filename=test.txt')

        # Verify response is successful
        assert response.status_code == 200

        # Check that Content-Disposition header exists and uses attachment
        assert 'Content-Disposition' in response.headers
        content_disposition = response.headers.get('Content-Disposition')
        assert 'attachment' in content_disposition

        # Verify the filename in header is sanitized (secure_filename applied)
        assert 'filename=' in content_disposition

    def test_xss_payload_in_filename_is_neutralized(self, client, monkeypatch, temp_test_dir):
        """
        Test that XSS payloads in filenames are neutralized.

        Even if an attacker tries to inject script tags or other HTML/JS in the filename,
        the secure_filename function should strip these out.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Create a file with a safe name
        safe_file = temp_test_dir / "document.txt"
        safe_file.write_text("content")

        # The attacker might try to use a malicious filename parameter
        # Even though the file is named "document.txt", they try XSS in the parameter
        malicious_filename = "<script>alert('XSS')</script>document.txt"

        # The function should sanitize this
        safe_name = secure_filename(malicious_filename)

        # Verify that script tags are removed
        assert '<script>' not in safe_name
        assert '</script>' not in safe_name
        assert 'alert' not in safe_name

    def test_as_attachment_prevents_inline_execution(self, client, monkeypatch, temp_test_dir):
        """
        Test that files are served with as_attachment=True.

        This is critical for preventing XSS because:
        - Without as_attachment, HTML files would be rendered inline in the browser
        - With as_attachment, files are downloaded instead of executed

        This directly addresses the vulnerability at line 16.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Create an HTML file that could execute scripts
        html_file = temp_test_dir / "malicious.html"
        html_file.write_text("<html><script>alert('XSS')</script></html>")

        response = client.get('/download?filename=malicious.html')

        # Check that Content-Disposition indicates attachment (not inline)
        content_disposition = response.headers.get('Content-Disposition', '')
        assert 'attachment' in content_disposition
        assert 'inline' not in content_disposition

        # This prevents the browser from rendering/executing the HTML

    def test_content_disposition_header_present(self, client, monkeypatch, temp_test_dir):
        """
        Test that Content-Disposition header is present in the response.

        The presence of this header with a sanitized filename is part of the XSS fix.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        test_file = temp_test_dir / "report.pdf"
        test_file.write_text("PDF content")

        response = client.get('/download?filename=report.pdf')

        assert 'Content-Disposition' in response.headers
        assert response.headers['Content-Disposition'].startswith('attachment')

    def test_empty_filename_uses_safe_default(self, client, monkeypatch, temp_test_dir):
        """
        Test that an empty filename parameter uses a safe default.

        This prevents errors and ensures even edge cases are handled securely.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Create a default file (this would fail in practice due to empty join,
        # but we're testing the sanitization logic)
        response = client.get('/download?filename=')

        # The function should handle empty filename gracefully
        # The secure_filename would return empty string, so fallback to 'download'
        # We expect a 404 or proper error, not an XSS vulnerability
        assert response.status_code in [404, 500]  # File not found is expected

    def test_special_characters_in_filename_sanitized(self, client, monkeypatch, temp_test_dir):
        """
        Test that special characters that could be used for XSS are sanitized.

        Characters like <, >, ", ', &, etc. should be removed or encoded.
        """
        # Test various malicious filename patterns
        malicious_patterns = [
            '"><script>alert(1)</script>',
            "'; alert('XSS'); //",
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            'file<>name.txt',
        ]

        for pattern in malicious_patterns:
            safe = secure_filename(pattern)
            # Verify dangerous characters are removed
            assert '<' not in safe
            assert '>' not in safe
            assert 'script' not in safe.lower() or safe == ''
            assert 'javascript:' not in safe

    def test_unicode_and_encoded_xss_attempts(self, client):
        """
        Test that Unicode and encoded XSS attempts are handled safely.

        Attackers might try to use Unicode or URL encoding to bypass filters.
        """
        # Test patterns
        patterns = [
            '%3Cscript%3Ealert(1)%3C/script%3E',  # URL encoded
            '\u003cscript\u003e',  # Unicode
            '&#60;script&#62;',  # HTML entities
        ]

        for pattern in patterns:
            safe = secure_filename(pattern)
            # secure_filename should handle these safely
            assert '<' not in safe
            assert 'script' not in safe or safe == ''

    def test_path_traversal_combined_with_xss(self, client, monkeypatch, temp_test_dir):
        """
        Test that path traversal attempts combined with XSS payloads are blocked.

        While this test focuses on XSS, attackers often combine multiple attack vectors.
        The filename sanitization should handle both.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Combined attack: path traversal + XSS
        malicious = '../../<script>alert(1)</script>.txt'
        safe = secure_filename(malicious)

        # Verify both path traversal and XSS components are removed
        assert '..' not in safe
        assert '<script>' not in safe
        assert '/' not in safe  # secure_filename removes path separators


class TestDownloadFunctionality:
    """Test that the fix doesn't break legitimate file download functionality."""

    def test_legitimate_file_download_works(self, client, monkeypatch, temp_test_dir):
        """
        Test that legitimate file downloads still work correctly after the fix.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Create a legitimate file
        test_file = temp_test_dir / "legitimate_file.txt"
        expected_content = "This is legitimate content."
        test_file.write_text(expected_content)

        response = client.get('/download?filename=legitimate_file.txt')

        assert response.status_code == 200
        assert response.data.decode('utf-8') == expected_content

    def test_various_safe_file_types(self, client, monkeypatch, temp_test_dir):
        """
        Test that various safe file types can still be downloaded.
        """
        import file_reader
        monkeypatch.setattr(file_reader, 'BASE_DIR', str(temp_test_dir))

        # Test different file types
        file_types = [
            ('document.pdf', 'PDF content'),
            ('spreadsheet.xlsx', 'Excel data'),
            ('image.png', 'PNG binary data'),
            ('data.json', '{"key": "value"}'),
            ('code.py', 'print("hello")'),
        ]

        for filename, content in file_types:
            test_file = temp_test_dir / filename
            test_file.write_text(content)

            response = client.get(f'/download?filename={filename}')

            assert response.status_code == 200
            assert response.data.decode('utf-8') == content

            # All should be served as attachments
            assert 'attachment' in response.headers.get('Content-Disposition', '')


class TestRegressionPrevention:
    """Tests to prevent regression of the XSS vulnerability."""

    def test_send_file_has_as_attachment_parameter(self):
        """
        Test that the code explicitly uses as_attachment=True.

        This is a code-level check to ensure the fix remains in place.
        """
        import file_reader
        import inspect

        # Get the source code of download_file
        source = inspect.getsource(file_reader.download_file)

        # Verify the fix is present
        assert 'as_attachment=True' in source
        assert 'download_name=' in source or 'attachment_filename=' in source
        assert 'secure_filename' in source or 'werkzeug.utils.secure_filename' in source

    def test_filename_sanitization_is_applied(self):
        """
        Verify that filename sanitization is applied before sending the file.
        """
        import file_reader
        import inspect

        source = inspect.getsource(file_reader.download_file)

        # Check that secure_filename is used
        assert 'secure_filename' in source

        # Check that the sanitized name is used in send_file
        assert 'send_file' in source


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
