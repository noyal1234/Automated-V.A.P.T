import nmap
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
import requests
import threading
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self, msf_host, msf_port, msf_username, msf_password):
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.msf_username = msf_username
        self.msf_password = msf_password
        self.client = None

    def connect_to_metasploit(self):
        try:
            self.client = MsfRpcClient(self.msf_password, port=self.msf_port, ssl=False)
            logging.info("Connected to Metasploit RPC server successfully.")
        except MsfRpcError as e:
            logging.error(f"Error connecting to Metasploit RPC server: {e}")

    def scan_ports_with_nmap(self, target):
        nm = nmap.PortScanner()
        try:
            if target.startswith('http://') or target.startswith('https://'):
                target = target.split('://')[1].split('/')[0]  # Extract host from URL
            logging.info(f"Scanning target: {target}")
            nm.scan(hosts=target, arguments='-p- -sV')  # Scan all ports and detect service versions
            open_ports = []
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        for port in lport:
                            if nm[host][proto][port]['state'] == 'open':
                                service_name = nm[host][proto][port]['name']
                                service_version = nm[host][proto][port]['version']
                                open_ports.append({'port': port, 'service': service_name, 'version': service_version})
            logging.info(f"Open ports detected: {open_ports}")
            return open_ports
        except nmap.PortScannerError as e:
            logging.error(f"Nmap scan error: {e}")
            return []

    def fetch_vulnerabilities(self, service_name, service_version):
        try:
            if service_name == 'http':
                return self.fetch_http_vulnerabilities(service_version)
            elif service_name == 'ftp':
                return self.fetch_ftp_vulnerabilities(service_version)
            elif service_name == 'ssh':
                return self.fetch_ssh_vulnerabilities(service_version)
            else:
                logging.info(f"No vulnerability information found for service {service_name}")
                return []
        except Exception as e:
            logging.error(f"Error fetching vulnerabilities: {e}")
            return []

    def fetch_http_vulnerabilities(self, service_version):
        try:
            logging.info(f"Fetching HTTP vulnerabilities for version: {service_version}")
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_version}&startIndex=0&resultsPerPage=10"
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                if 'result' in data and 'CVE_Items' in data['result']:
                    for item in data['result']['CVE_Items']:
                        cve_id = item['cve']['CVE_data_meta']['ID']
                        description = item['cve']['description']['description_data'][0]['value']
                        vulnerabilities.append(f"{cve_id}: {description}")
                logging.info(f"Found vulnerabilities: {vulnerabilities}")
                return vulnerabilities
            else:
                logging.error(f"Failed to fetch HTTP vulnerabilities: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching HTTP vulnerabilities: {e}")
            return []

    def fetch_ftp_vulnerabilities(self, service_version):
        try:
            logging.info(f"Fetching FTP vulnerabilities for version: {service_version}")
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keyword=ftp+{service_version}&startIndex=0&resultsPerPage=10"
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                for item in data['cves']:
                    cve_id = item['cve_id']
                    description = item['description']
                    vulnerabilities.append(f"{cve_id}: {description}")
                logging.info(f"Found vulnerabilities: {vulnerabilities}")
                return vulnerabilities
            else:
                logging.error(f"Failed to fetch FTP vulnerabilities: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching FTP vulnerabilities: {e}")
            return []

    def fetch_ssh_vulnerabilities(self, service_version):
        try:
            logging.info(f"Fetching SSH vulnerabilities for version: {service_version}")
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keyword=ssh+{service_version}&startIndex=0&resultsPerPage=10"
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                for item in data['cves']:
                    cve_id = item['cve_id']
                    description = item['description']
                    vulnerabilities.append(f"{cve_id}: {description}")
                logging.info(f"Found vulnerabilities: {vulnerabilities}")
                return vulnerabilities
            else:
                logging.error(f"Failed to fetch SSH vulnerabilities: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching SSH vulnerabilities: {e}")
            return []

    def list_vulnerabilities(self, open_ports):
        try:
            threads = []
            for port_info in open_ports:
                port = port_info['port']
                service = port_info['service']
                version = port_info['version']
                thread = threading.Thread(target=self.log_vulnerabilities, args=(service, version, port))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()
        except MsfRpcError as e:
            logging.error(f"Error listing vulnerabilities: {e}")

    def log_vulnerabilities(self, service, version, port):
        vulnerabilities = self.fetch_vulnerabilities(service, version)
        if vulnerabilities:
            logging.info(f"Vulnerabilities for {service} (version {version}), port {port}:")
            for vuln in vulnerabilities:
                logging.info(f"- {vuln}")
        else:
            logging.info(f"No vulnerabilities found for {service} (version {version}), port {port}")

if __name__ == "__main__":
    start_time = time.time()

    msf_host = '127.0.0.1'  # Replace with your Metasploit host IP
    msf_port = 55552        # Replace with your Metasploit RPC port
    msf_username = 'msf'    # Replace with your Metasploit username
    msf_password = 'coder12'  # Replace with your Metasploit password

    target = 'http://www.itsecgames.com/index.htm'  # Replace with your target IP or URL

    scanner = VulnerabilityScanner(msf_host, msf_port, msf_username, msf_password)
    scanner.connect_to_metasploit()

    open_ports = scanner.scan_ports_with_nmap(target)
    if open_ports:
        logging.info(f"Open ports detected by Nmap: {open_ports}")
        scanner.list_vulnerabilities(open_ports)
    else:
        logging.info("No open ports detected.")

    end_time = time.time()
    logging.info(f"Execution time: {end_time - start_time} seconds")
