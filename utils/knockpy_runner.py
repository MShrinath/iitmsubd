import ssl, socket, json, os
from knock import KNOCKPY

def get_full_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject_common_name": next((t[0][1] for t in cert["subject"] if t[0][0] == "commonName"), None),
                    "issuer_common_name": next((t[0][1] for t in cert["issuer"] if t[0][0] == "commonName"), None),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber", None),
                    "full_raw": cert
                }
    except Exception as e:
        return {"error": str(e)}

def run_knockpy_and_enhance_streaming(domain, save_path):
    yield f"[+] Running Knockpy on {domain}..."
    results = KNOCKPY(domain, recon=True, bruteforce=True)

    # Load existing results if available
    if os.path.exists(save_path):
        with open(save_path, 'r') as f:
            try:
                existing_data = {entry["domain"]: entry for entry in json.load(f)}
            except Exception:
                existing_data = {}
    else:
        existing_data = {}

    yield f"[+] Found {len(results)} subdomains. Starting cert collection..."

    for idx, entry in enumerate(results):
        subdomain = entry.get("domain")
        yield f"    ↳ Fetching cert for {subdomain} ({idx + 1}/{len(results)})"
        
        cert_data = get_full_certificate(subdomain)
        entry["cert_details"] = cert_data

        # Update if already present, otherwise add new
        existing_data[subdomain] = entry

    # Convert dict back to list and save
    with open(save_path, 'w') as f:
        json.dump(list(existing_data.values()), f, indent=4)

    yield f"✅ Rescan complete."
    print(f"[+] Results saved to {save_path}")
