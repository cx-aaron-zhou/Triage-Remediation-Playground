import os
from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = "/var/www/static"

# A01:Broken Access Control — Path Traversal
# User-supplied filename is joined to a base directory without sanitization.
# An attacker can supply: ../../../../etc/passwd to read arbitrary files.

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    file_path = os.path.join(BASE_DIR, filename)
    return send_file(file_path)

def read_report(report_name: str) -> str:
    file_path = BASE_DIR + "/" + report_name
    with open(file_path, 'r') as f:
        return f.read()
