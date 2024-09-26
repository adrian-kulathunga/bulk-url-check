import requests
import time
import argparse

#  VirusTotal API key
API_KEY = 'API'

# File containing URLs
#url_file = 'urls.txt'
parser = argparse.ArgumentParser(description='Input File')
parser.add_argument('url_file', help = "Path to input text")

args = parser.parse_args()

# Base URL for api
base_url = 'https://www.virustotal.com/vtapi/v2/url/scan'

def scan_url(url):
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(base_url, data=params)
    if response.status_code == 200:
        return response.json()
    else:
    else:
        return None

def get_report(scan_id):
    report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': scan_id}
    response = requests.get(report_url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Read URLs from file
with open(args.url_file, 'r') as file:
    urls = file.readlines()

# Scan URLs and get reports
for url in urls:
    url = url.strip()
    print(f'Scanning URL: {url}')
    scan_result = scan_url(url)
    if scan_result and 'scan_id' in scan_result:
        time.sleep(61)  # Sleep to respect API rate limits
        report = get_report(scan_result['scan_id'])
        if report:
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            if positives > 0:
                print(f'URL: {url} is MALICIOUS. Detected by {positives}/{total} scanners.')
            else:
                print(f'URL: {url} is CLEAN. Detected by {positives}/{total} scanners.')
        else:
            print(f'Failed to get report for URL: {url}')
    else:
        print(f'Failed to scan URL: {url}')
