import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# SAST: A08:Software and Data Integrity Failures — Unsafe Deserialization / Arbitrary Code Execution
# SCA:  PyYAML 5.3.1 → CVE-2020-14343 (CVSS 9.8)
#
# yaml.load() without an explicit Loader accepts !!python/object tags,
# allowing an attacker to instantiate arbitrary Python objects and achieve RCE.
# Example payload: "!!python/object/apply:os.system ['id']"

@app.route('/config', methods=['POST'])
def load_config():
    raw = request.data.decode('utf-8')
    config = yaml.safe_load(raw)     # safe — prevents arbitrary code execution
    return jsonify(config)
