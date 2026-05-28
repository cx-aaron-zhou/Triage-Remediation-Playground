import yaml
from flask import Flask, request, jsonify, make_response
import html

app = Flask(__name__)

# SAST: A08:Software and Data Integrity Failures — Unsafe Deserialization / Arbitrary Code Execution
# SCA:  PyYAML 5.3.1 → CVE-2020-14343 (CVSS 9.8)
#
# yaml.load() without an explicit Loader accepts !!python/object tags,
# allowing an attacker to instantiate arbitrary Python objects and achieve RCE.
# Example payload: "!!python/object/apply:os.system ['id']"

def sanitize_value(value):
    """
    Recursively sanitize values to prevent XSS attacks by escaping HTML characters.
    This prevents malicious scripts from being injected through user-controlled data.
    """
    if isinstance(value, str):
        # Escape HTML special characters to prevent XSS
        return html.escape(value, quote=True)
    elif isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_value(item) for item in value]
    elif isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)
    else:
        # For other types (int, float, bool, None), return as-is
        return value

@app.route('/config', methods=['POST'])
def load_config():
    raw = request.data.decode('utf-8')
    config = yaml.load(raw)          # unsafe — should be yaml.safe_load()
    # Sanitize config data to prevent XSS attacks before returning
    sanitized_config = sanitize_value(config)
    response = make_response(jsonify(sanitized_config))
    # Set security headers to prevent XSS
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
