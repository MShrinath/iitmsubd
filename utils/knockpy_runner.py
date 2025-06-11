import ssl, socket, datetime, requests
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

def get_mxtoolbox_data(domain, api_key):
    try:
        url = f"https://api.mxtoolbox.com/api/v1/lookup/dns/{domain}?authorization={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": True,
                "status": response.status_code,
                "message": response.text
            }
    except Exception as e:
        return {"error": True, "message": str(e)}

def get_dnsdumpster_data(domain, dnsdumpster_api_key):
    try:
        url = f"https://api.dnsdumpster.com/domain/{domain}"
        headers = {
            "X-API-Key": dnsdumpster_api_key
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": True,
                "status": response.status_code,
                "message": response.text
            }
    except Exception as e:
        return {"error": True, "message": str(e)}

def run_knockpy_and_enhance_streaming(domain, collection, mxtoolbox_api_key, dnsdumpster_api_key):
    yield f"[+] Running Knockpy on {domain}..."
    results = KNOCKPY(domain, recon=True, bruteforce=True)

    yield f"[+] Found {len(results)} subdomains. Starting data enrichment..."

    for idx, entry in enumerate(results):
        subdomain = entry.get("domain")
        yield f"    ↳ {idx+1}/{len(results)}: {subdomain} → Fetching cert + MXToolbox + DNSDumpster"

        # SSL Certificate
        cert_data = get_full_certificate(subdomain)

        # MXToolbox
        mxtoolbox_data = get_mxtoolbox_data(subdomain, mxtoolbox_api_key)

        # DNSDumpster
        dnsdumpster_data = get_dnsdumpster_data(subdomain, dnsdumpster_api_key)

        # Update entry
        entry["domain"] = subdomain
        entry["cert_details"] = cert_data
        entry["mxtoolbox"] = mxtoolbox_data
        entry["dnsdumpster"] = dnsdumpster_data
        entry["scanned_at"] = datetime.datetime.utcnow().isoformat()

        # Store in MongoDB
        collection.update_one(
            {"domain": subdomain},
            {"$set": entry},
            upsert=True
        )

    yield "✅ Rescan + enrichment complete."
