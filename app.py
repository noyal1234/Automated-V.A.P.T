from flask import Flask, request, jsonify
import subprocess
import re
import joblib
import pandas as pd
from nmap_scan import run_nmap_scan, parse_nmap_result
from openvas_scan import OpenVASScanner
from metasploit_scan import MetasploitScanner

app = Flask(__name__)

# Load pre-trained model
model = joblib.load('vulnerability_model.pkl')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.json['target']
    nmap_output = run_nmap_scan(target)
    vulnerabilities = parse_nmap_result(nmap_output)
    
    results = []
    for port, service in vulnerabilities:
        df = pd.DataFrame({'port': [port], 'service': [service]})
        df = pd.get_dummies(df)
        severity = model.predict(df)[0]
        results.append({'port': port, 'service': service, 'severity': severity})
    
    return jsonify(results)

@app.route('/openvas_scan', methods=['POST'])
def openvas_scan():
    target = request.json['target']
    scanner = OpenVASScanner(username='admin', password='admin')
    results = scanner.scan(target)
    return jsonify(results)

@app.route('/metasploit_scan', methods=['POST'])
def metasploit_scan():
    target = request.json['target']
    scanner = MetasploitScanner(password='your_password')
    results = scanner.scan(target)
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
