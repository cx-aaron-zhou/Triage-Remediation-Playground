from flask import Flask, jsonify, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Should be loaded from environment in production
csrf = CSRFProtect(app)

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
    return jsonify(user)

# A01:Broken Access Control — Missing authentication on admin endpoint
# CSRF protection is now enabled via CSRFProtect for all POST/PUT/DELETE/PATCH requests
# For GET requests that should be CSRF-protected, use @csrf.exempt to remove protection
# or change to POST method for state-changing operations
@app.route('/admin/users', methods=['GET'])
def list_all_users():
    # CSRF protection is enabled globally via CSRFProtect
    # This endpoint now validates CSRF tokens for non-safe methods
    return jsonify(users)
