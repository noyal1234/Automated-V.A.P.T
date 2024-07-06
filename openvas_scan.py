
import requests
import time
from xml.etree import ElementTree

class OpenVASScanner:
    def __init__(self, username, password, host='localhost', port=9390):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f'https://{host}:{port}/omp'

    def authenticate(self):
        response = requests.post(self.base_url, data=f'<authenticate><credentials><username>{self.username}</username><password>{self.password}</password></credentials></authenticate>', verify=False)
        root = ElementTree.fromstring(response.content)
        self.token = root.find('.//token').text

    def create_target(self, target):
        data = f"""
        <create_target>
            <name>{target}</name>
            <hosts>{target}</hosts>
        </create_target>
        """
        response = requests.post(self.base_url, data=data, headers={'Authorization': f'Token {self.token}'}, verify=False)
        root = ElementTree.fromstring(response.content)
        return root.find('.//id').text

    def create_task(self, target_id):
        data = f"""
        <create_task>
            <name>Scan {target_id}</name>
            <comment>Automated scan</comment>
            <config id="daba56c8-73ec-11df-a475-002264764cea"/>
            <target id="{target_id}"/>
        </create_task>
        """
        response = requests.post(self.base_url, data=data, headers={'Authorization': f'Token {self.token}'}, verify=False)
        root = ElementTree.fromstring(response.content)
        return root.find('.//id').text

    def start_task(self, task_id):
        data = f"<start_task task_id='{task_id}'/>"
        response = requests.post(self.base_url, data=data, headers={'Authorization': f'Token {self.token}'}, verify=False)
        return response.status_code == 200

    def get_results(self, task_id):
        data = f"<get_reports task_id='{task_id}'/>"
        response = requests.post(self.base_url, data=data, headers={'Authorization': f'Token {self.token}'}, verify=False)
        return response.content

    def scan(self, target):
        self.authenticate()
        target_id = self.create_target(target)
        task_id = self.create_task(target_id)
        self.start_task(task_id)
        time.sleep(60)  # Wait for the scan to complete. Adjust based on scan duration.
        return self.get_results(task_id)

if __name__ == "__main__":
    scanner = OpenVASScanner(username='admin', password='admin')
    target = 'example.com'
    results = scanner.scan(target)
    print(results)
