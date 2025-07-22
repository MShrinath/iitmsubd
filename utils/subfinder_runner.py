import xmltodict
import json
import subprocess
import os


# Define paths
base_dir = os.path.dirname(__file__)
tools_dir = os.path.join(base_dir, '..', 'tools')

subfinder_path = os.path.join(tools_dir, 'subfinder.exe')
dnsx_path = os.path.join(tools_dir, 'dnsx.exe')
sslscan_path = os.path.join(tools_dir, 'sslscan.exe')
wappalyzer_path = os.path.join(tools_dir, 'wappalyzer.exe')

sub_out = os.path.join(tools_dir, 'txt', 'subfinder_output.txt')
dnsx_out = os.path.join(tools_dir, 'txt', 'dnsx_output.json')
dnsx_hout = os.path.join(tools_dir, 'txt', 'dnsx_hosts.txt')
sslscan_out = os.path.join(tools_dir, 'txt', 'sslscan_output.json')
wap_out = os.path.join(tools_dir, 'txt', 'wappalyzer_output.json')
wap_out_temp = os.path.join(tools_dir, 'txt', 'wappalyzer_output_temp.json')

FINAL_DATA = os.path.join(base_dir, '..','data', 'final_data.json')



def base_info():
    # print(f"[INFO] Starting subdomain enumeration for: {domain}")
    print(f"[INFO] Base directory: {base_dir}")
    print(f"[INFO] Tools directory: {tools_dir}")
    print(f"[INFO] Subfinder path: {subfinder_path}")
    print(f"[INFO] DNSx path: {dnsx_path}")
    print(f"[INFO] SSLScan path: {sslscan_path}")
    print(f"[INFO] Subfinder output path: {sub_out}")
    print(f"[INFO] DNSx output path: {dnsx_out}")
    print(f"[INFO] Final output path: {FINAL_DATA}")



def run(domain):

    print(f"----[INFO] Running subfinder for: {domain}")
    # --- 1. Run subfinder ---
    with open(sub_out, 'w') as sf_out:
        subprocess.run([subfinder_path, "-d", domain, "-silent"], stdout=sf_out)




    print(f"----[INFO] Running dnsx...")
    # --- 2. Run dnsx ---     dnsx_in == sub_out
    with open(sub_out, 'r') as sf_in, open(dnsx_out, 'w') as dx_out:
        subprocess.run([dnsx_path, "-silent", "-json"], stdin=sf_in, stdout=dx_out)

    with open(dnsx_out, 'r',encoding='utf-8') as f:
        results = [json.loads(line) for line in f if line.strip()]
    os.remove(dnsx_out)  
    with open(dnsx_out, 'w') as out_f:
        json.dump(results, out_f, indent=4)









    print(f"---[INFO] Processing dnsx output and filtering hosts...")
    # --- 3. Extract hosts from dnsx and filter ---
    with open(dnsx_out, 'r') as dx_in:
        try:
            data_list = json.load(dx_in)  # Load entire JSON array
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to decode JSON from {dnsx_out}: {e}")

    hosts = []
    for entry in data_list:
        host = entry.get("host")
        if host:
            hosts.append(host)

    # Filter: only hosts ending with the target domain
    filtered_hosts = []
    for host in hosts:
        if host.endswith(domain):
            filtered_hosts.append(host)
        else:
            print(f"[WARN] Ignored unrelated host from dnsx: {host}")

    if not filtered_hosts:
        print(f"[WARN] No valid subdomains found for {domain}")

    print(f"---[INFO] Found {len(filtered_hosts)} valid subdomains for {domain}")
    # --- 4. Get dnsx hosts ---
    with open(dnsx_hout, 'w') as f:
        for h in filtered_hosts:
            f.write(h + '\n')




    print(f"----[INFO] Running sslscan on {len(filtered_hosts)} hosts...")
    # --- 5. Run sslscan ---
    with open(dnsx_hout, 'r') as ssl_in, open(sslscan_out, 'w') as sslscan_out_file:
        all_results = {}

        for line in ssl_in:
            host = line.strip()
            if not host:
                continue

            print(f"Scanning {host}...")

            try:
                # Capture XML output directly from sslscan
                result = subprocess.run(
                    [sslscan_path, "--no-ciphersuites", "--no-cipher-details", "--no-renegotiation",
                    "--no-heartbleed", "--no-fallback", "--no-groups", "--xml=-", host],
                    capture_output=True,
                    text=True
                )

                xml_content = result.stdout.strip()

                if not xml_content.startswith('<?xml'):
                    print(f"[WARN] Skipping non-XML response for {host}")
                    continue

                data_dict = xmltodict.parse(xml_content)
                document = data_dict.get("document", {})

                if "error" in document:
                    error_msg = document["error"]
                    all_results[host] = {"cert_details": {"error": error_msg}}

                else:
                    cert_details = document.get("ssltest", {}).get("certificates", {}).get("certificate", {})
                    all_results[host] = {"cert_details": cert_details}

            except Exception as e:
                print(f"[ERROR] Failed to convert SSLScan output for {host} to JSON: {e}")
                continue

        json.dump(all_results, sslscan_out_file, indent=4)
    print(f"[INFO] SSLScan results saved to {sslscan_out}") 



















    print(f"----[INFO] getting techstack with wapalyzer...")
    # --- 6. Get techstack with wapalyzer ---
    with open(dnsx_hout, 'r') as wap_in, open(wap_out, 'w') as wp_out:
        all_results = {}

        for line in wap_in:
            host = line.strip()
            print(f"Analyzing {host} with Wappalyzer...")
            result = subprocess.run(
                [wappalyzer_path, "-i", host, "-t 10", "--scan-type", "balanced", "-oJ", wap_out_temp],
                capture_output=True,
                text=True
            )

            with open(wap_out_temp, 'r', encoding='utf-8') as f:
                wap_data = json.load(f)

                for url, techs in wap_data.items():
                    tech_names = list(techs.keys())
                
                if tech_names == []:
                    all_results[host] = {"techstack": ["No technologies found"]}
                else:
                    all_results[host] = {"techstack": tech_names}

        json.dump(all_results, wp_out, indent=4)
    print(f"[INFO] Wappalyzer results saved to {wap_out}")
    os.remove(wap_out_temp)


run("iitm.ac.in")  