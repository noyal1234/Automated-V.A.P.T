from flask import Flask, jsonify
import json
app = Flask(__name__)

with open('nvdcve-1.1-2024.json', 'r', encoding='utf-8') as file:
    nvd_data = json.load(file)

@app.route('/vulnerabilities/<string:service_version>', methods=['GET'])
def get_vulnerabilities(service_version):
    results = []
    for item in nvd_data['CVE_Items']:
        if service_version in item['cve']['description']['description_data'][0]['value']:
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            results.append({"cve_id": cve_id, "description": description})
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
