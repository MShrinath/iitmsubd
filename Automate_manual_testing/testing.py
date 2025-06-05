# import socket
# import requests
# import csv
# import json
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from datetime import datetime

# # Disable SSL warnings for testing
# requests.packages.urllib3.disable_warnings()

# def log(message, level="INFO"):
#     timestamp = datetime.now().strftime("%H:%M:%S")
#     print(f"[{timestamp}] [{level}] {message}")

# # Load subdomains from JSON file
# def load_domains_from_json(file_path):
#     with open(file_path, 'r') as f:
#         data = json.load(f)
#     return [entry['domain'] for entry in data if 'domain' in entry]

# # Check each domain
# def check_subdomain(domain):
#     result = {
#         'domain': domain,
#         'dns_resolves': False,
#         'ip_address': '',
#         'http_status': '',
#         'https_status': '',
#         'notes': ''
#     }

#     notes = []  # Collect multiple notes

#     log(f"Testing: {domain}")

#     # DNS Lookup
#     try:
#         ip = socket.gethostbyname(domain)
#         result['dns_resolves'] = True
#         result['ip_address'] = ip
#         log(f"  ✓ DNS Resolved: {ip}", level="SUCCESS")
#     except socket.gaierror:
#         notes.append('DNS resolution failed')
#         log("  ✗ DNS resolution failed", level="ERROR")
#         result['notes'] = '; '.join(notes)
#         return result

#     # HTTP Check
#     try:
#         http_resp = requests.get(f"http://{domain}", timeout=5)
#         result['http_status'] = http_resp.status_code
#         log(f"  ✓ HTTP Status: {http_resp.status_code}", level="SUCCESS")
#     except requests.RequestException as e:
#         result['http_status'] = 'Failed'
#         notes.append(f"HTTP request failed: {e}")
#         log(f"  ✗ HTTP request failed: {e}", level="ERROR")

#     # HTTPS Check
#     try:
#         https_resp = requests.get(f"https://{domain}", timeout=5, verify=False)
#         result['https_status'] = https_resp.status_code
#         log(f"  ✓ HTTPS Status: {https_resp.status_code}", level="SUCCESS")
#     except requests.RequestException as e:
#         result['https_status'] = 'Failed'
#         notes.append(f"HTTPS request failed: {e}")
#         log(f"  ✗ HTTPS request failed: {e}", level="ERROR")

#     # Combine all notes (if any)
#     if notes:
#         result['notes'] = '; '.join(notes)

#     return result

# def main():
#     input_file = '../data/iitm.ac.in_knockpy_results_with_certs.json'
#     output_file = 'manual_verification_report.csv'

#     log("Loading domains from JSON...")
#     domains = load_domains_from_json(input_file)
#     log(f"Total domains loaded: {len(domains)}\n")

#     results = []
#     with ThreadPoolExecutor(max_workers=10) as executor:
#         future_to_domain = {executor.submit(check_subdomain, domain): domain for domain in domains}
#         for future in as_completed(future_to_domain):
#             results.append(future.result())

#     # Write to CSV
#     log("\nWriting results to CSV...")
#     with open(output_file, 'w', newline='') as csvfile:
#         fieldnames = ['domain', 'dns_resolves', 'ip_address', 'http_status', 'https_status', 'notes']
#         writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
#         writer.writeheader()
#         for res in results:
#             writer.writerow(res)

#     log(f"Manual verification report saved to '{output_file}'", level="SUCCESS")

# if __name__ == "__main__":
#     main()
import socket
import requests
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

# Load subdomains from JSON file
def load_domains_from_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return [entry['domain'] for entry in data if 'domain' in entry]

# Check each domain
def check_subdomain(domain):
    result = {
        'domain': domain,
        'dns_resolves': False,
        'ip_address': '',
        'http_status': '',
        'https_status': '',
        'notes': ''
    }

    notes = []  # Collect multiple notes

    log(f"Testing: {domain}")

    # DNS Lookup
    try:
        ip = socket.gethostbyname(domain)
        result['dns_resolves'] = True
        result['ip_address'] = ip
        log(f"  ✓ DNS Resolved: {ip}", level="SUCCESS")
    except socket.gaierror:
        notes.append('DNS resolution failed')
        log("  ✗ DNS resolution failed", level="ERROR")
        result['notes'] = '; '.join(notes)
        return result

    # HTTP Check
    try:
        http_resp = requests.get(f"http://{domain}", timeout=5)
        result['http_status'] = http_resp.status_code
        log(f"  ✓ HTTP Status: {http_resp.status_code}", level="SUCCESS")
    except requests.RequestException as e:
        result['http_status'] = 'Failed'
        notes.append(f"HTTP request failed: {e}")
        log(f"  ✗ HTTP request failed: {e}", level="ERROR")

    # HTTPS Check
    try:
        https_resp = requests.get(f"https://{domain}", timeout=5, verify=False)
        result['https_status'] = https_resp.status_code
        log(f"  ✓ HTTPS Status: {https_resp.status_code}", level="SUCCESS")
    except requests.RequestException as e:
        result['https_status'] = 'Failed'
        notes.append(f"HTTPS request failed: {e}")
        log(f"  ✗ HTTPS request failed: {e}", level="ERROR")

    # Combine all notes (if any)
    if notes:
        result['notes'] = '; '.join(notes)

    return result

def main():
    input_file = '../data/iitm.ac.in_knockpy_results_with_certs.json'
    output_file = 'manual_verification_report.csv'

    log("Loading domains from JSON...")
    domains = load_domains_from_json(input_file)
    total_domains = len(domains)
    log(f"Total domains loaded: {total_domains}\n")

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(check_subdomain, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            results.append(future.result())

    # Count successful resolutions
    dns_success = sum(1 for r in results if r['dns_resolves'])
    http_success = sum(1 for r in results if str(r['http_status']).isdigit() and int(r['http_status']) < 400)
    https_success = sum(1 for r in results if str(r['https_status']).isdigit() and int(r['https_status']) < 400)

    # Write to CSV
    log("\nWriting results to CSV...")
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['domain', 'dns_resolves', 'ip_address', 'http_status', 'https_status', 'notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res)

    log(f"Manual verification report saved to '{output_file}'", level="SUCCESS")

    # Final summary comment
    log("\nSummary:")
    log(f"Total domains scanned: {total_domains}")
    log(f"Out of these, {dns_success} subdomains successfully resolved via DNS.")
    log(f"{http_success} subdomains responded successfully to HTTP requests.")
    log(f"{https_success} subdomains responded successfully to HTTPS requests.")

if __name__ == "__main__":
    main()
