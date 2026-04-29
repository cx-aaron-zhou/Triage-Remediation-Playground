from flask import Flask, jsonify, request, make_response
from markupsafe import escape

app = Flask(__name__)

users = {
    "1": {"name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789", "role": "user"},
    "2": {"name": "Bob",   "email": "bob@example.com",   "ssn": "987-65-4321", "role": "admin"},
}

# A01:Broken Access Control — IDOR
# No session check: any caller can read any user record, including sensitive fields (SSN)
@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    # XSS Prevention: Sanitize user data before returning it
    # Escape HTML special characters in all string values
    sanitized_user = {
        key: escape(str(value)) if isinstance(value, str) else value
        for key, value in user.items()
    }
    response = make_response(jsonify(sanitized_user))
    # Add security headers to prevent XSS
    response.headers['Content-Type'] = 'application/json'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# A01:Broken Access Control — Missing authentication on admin endpoint
@app.route('/admin/users', methods=['GET'])
def list_all_users():
    return jsonify(users)
