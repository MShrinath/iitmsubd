import os
import json
import subprocess
import xmltodict
import requests

# Paths setup
base_dir = os.path.dirname(__file__)
tools_dir = os.path.join(base_dir, '..', 'tools')

subfinder_path = os.path.join(tools_dir, 'subfinder.exe')
dnsx_path = os.path.join(tools_dir, 'dnsx.exe')
sslscan_path = os.path.join(tools_dir, 'sslscan.exe')
wappalyzer_path = os.path.join(tools_dir, 'wappalyzer.exe')

sub_out = os.path.join(tools_dir, 'txt', f'{domain}_subfinder_output.txt')
dnsx_out = os.path.join(tools_dir, 'txt', f'{domain}_dnsx_output.json')
dnsx_hout = os.path.join(tools_dir, 'txt', f'{domain}_dnsx_hosts.txt')
sslscan_out = os.path.join(tools_dir, 'txt', f'{domain}_sslscan_output.json')
wap_out = os.path.join(tools_dir, 'txt', f'{domain}_wappalyzer_output.json')
wap_out_temp = os.path.join(tools_dir, 'txt', f'{domain}_wappalyzer_output_temp.json')
http_status_out = os.path.join(tools_dir, 'txt', f'{domain}_http_status.json')

# FINAL_DATA = os.path.join(base_dir, '..', 'data', 'final_data.json')


def update_final_data(host, field, value):
    data = []
    if os.path.exists(FINAL_DATA):
        with open(FINAL_DATA, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

    for entry in data:
        if entry.get("subdomain") == host:
            entry[field] = value
            break
    else:
        new_entry = {"subdomain": host, field: value}
        data.append(new_entry)

    with open(FINAL_DATA, 'w') as f:
        json.dump(data, f, indent=4)


def run_subfinder(domain):
    print(f"[INFO] Running subfinder for: {domain}")
    with open(sub_out, 'w') as sf_out:
        subprocess.run([subfinder_path, "-d", domain, "-silent"], stdout=sf_out)


def run_dnsx(domain):
    print("[INFO] Running dnsx")
    with open(sub_out, 'r') as sf_in, open(dnsx_out, 'w') as dx_out:
        subprocess.run([dnsx_path, "-silent", "-json"], stdin=sf_in, stdout=dx_out)

    with open(dnsx_out, 'r', encoding='utf-8') as f:
        results = [json.loads(line) for line in f if line.strip()]
    with open(dnsx_out, 'w') as out_f:
        json.dump(results, out_f, indent=4)


def extract_and_filter_hosts(domain):
    print("[INFO] Extracting and filtering DNSx results")
    with open(dnsx_out, 'r') as f:
        try:
            data_list = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse dnsx output: {e}")
            return []

    hosts = []
    with open(dnsx_hout, 'w') as out:
        for entry in data_list:
            host = entry.get("host")
            if not host or not host.endswith(domain):
                continue

            hosts.append(host)
            ip_list = entry.get("a", ["ip not resolved"])
            update_final_data(host, "ip", ip_list)
            out.write(host + '\n')

    print(f"[INFO] Found {len(hosts)} valid subdomains")
    return hosts


def run_sslscan(hosts):
    print("[INFO] Running SSLScan")
    with open(sslscan_out, 'w') as ssl_out:
        results = {}
        for host in hosts:
            print(f"Scanning SSL for {host}...")
            try:
                result = subprocess.run(
                    [sslscan_path, "--no-ciphersuites", "--no-cipher-details", "--no-renegotiation",
                    "--no-heartbleed", "--no-fallback", "--no-groups", "--xml=-", host],
                    capture_output=True, text=True
                )
                xml_content = result.stdout.strip()
                if not xml_content.startswith('<?xml'):
                    raise ValueError("Invalid SSLScan output")

                data_dict = xmltodict.parse(xml_content)
                document = data_dict.get("document", {})

                if "error" in document:
                    # Handle the <error> tag in XML
                    error_msg = document["error"]
                    cert_details = {"error": error_msg}
                else:
                    cert_details = document.get("ssltest", {}).get("certificates", {}).get("certificate", {})

                results[host] = {"cert_details": cert_details}
                update_final_data(host, "cert_details", cert_details)

            except Exception as e:
                print(f"[ERROR] SSLScan failed for {host}: {e}")
                error_msg = {"error": "Certificate information couldnt be retrieved."}
                results[host] = {"cert_details": error_msg}
                update_final_data(host, "cert_details", error_msg)

        json.dump(results, ssl_out, indent=4)


def run_wappalyzer(hosts):
    print("[INFO] Running Wappalyzer")
    with open(wap_out, 'w') as wap_out_file:
        results = {}
        for host in hosts:
            print(f"Analyzing {host} with Wappalyzer...")
            subprocess.run([
                wappalyzer_path, "-i", host, "-t", "10", "--scan-type", "balanced", "-oJ", wap_out_temp
            ], capture_output=True)

            try:
                with open(wap_out_temp, 'r', encoding='utf-8') as f:
                    wap_data = json.load(f)
                    for _, techs in wap_data.items():
                        tech_names = list(techs.keys()) or ["No technologies found"]
                        update_final_data(host, "techstack", tech_names)
                        results[host] = {"techstack": tech_names}
            except Exception:
                update_final_data(host, "techstack", ["Error"])
        json.dump(results, wap_out_file, indent=4)
        os.remove(wap_out_temp)


def check_http_https_status(hosts):
    print("[INFO] Checking HTTP/HTTPS status")
    results = {}
    for host in hosts:
        results[host] = {}
        print(f"Checking HTTP/HTTPS status for {host}...")
        for proto in ["http", "https"]:
            url = f"{proto}://{host}"
            field = "http_Status" if proto == "http" else "https_Status"
            try:
                r = requests.head(url, timeout=5)
                update_final_data(host, field, str(r.status_code))
                results[host][field] = str(r.status_code)
            except Exception:
                update_final_data(host, field, "timeout")
                results[host][field] = "timeout"
    with open(http_status_out, 'w') as f:
        json.dump(results, f, indent=4)


def run_subfinder(target,SUBFINDER_DATA_FILE):
    global domain
    global FINAL_DATA  
    domain = target
    FINAL_DATA = SUBFINDER_DATA_FILE
    print(f"[INFO] Starting scan for domain: {domain}\n")
    run_subfinder(domain)
    run_dnsx(domain)
    hosts = extract_and_filter_hosts(domain)
    if not hosts:
        print("[ERROR] No valid subdomains found.")
        return
    run_sslscan(hosts)
    run_wappalyzer(hosts)
    check_http_https_status(hosts)
    print(f"\n[INFO] Scan complete. Final data saved to: {FINAL_DATA}")


# Example usage:
run_subfinder("iitm.ac.in", "subfinderdummmmmyyoutput.txt")
