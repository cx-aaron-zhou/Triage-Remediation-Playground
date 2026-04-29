import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIXED: Upgraded PyYAML from 5.3.1 to 6.0.3 (CVE-2020-14343 remediation)
# Changed yaml.load() to yaml.safe_load() to prevent arbitrary code execution
# yaml.safe_load() only constructs simple Python objects (strings, lists, dicts)
# and rejects dangerous constructs like !!python/object tags

@app.route('/config', methods=['POST'])
def load_config():
    raw = request.data.decode('utf-8')
    config = yaml.safe_load(raw)     # safe — prevents arbitrary code execution
    return jsonify(config)
