import subprocess
import json
from datetime import datetime

def run_nmap_raw(target, save_path):
    print(f"Running Nmap scan on {target}...")

    try:
        # Run Nmap command
        command = ["nmap", "-Pn", "--top-ports", "1000", "-T4", "-sV", "--script=vuln", target]
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        # Attempt to load the JSON file and append the result
        try:
            with open(save_path, "r") as f:
                data = json.load(f)

            now_ist = datetime.now().isoformat() + "Z"

            for entry in data:
                if target in entry.get("ip", []):
                    entry["nmap_raw"] = output
                    entry["nmap_updated_at"] = now_ist

            with open(save_path, "w") as f:
                json.dump(data, f, indent=4)
            print(f"✅ Appended Nmap output to {target} in {save_path}")

        except Exception as e:
            print(f"❌ Error updating JSON file: {e}")

        return output, now_ist

    except subprocess.CalledProcessError as e:
        return f"❌ Nmap scan failed!\n---\nError Output:\n{e.stderr or str(e)}\n---"
    except Exception as e:
        return f"❌ Unexpected error during Nmap scan!\n---\nDetails: {str(e)}\n---"

def show_nmap(ip, data_file):
    try:
        with open(data_file, "r") as f:
            data = json.load(f)

        for entry in data:
            if ip in entry.get("ip", []):
                nmap_raw = entry.get("nmap_raw", "")
                nmap_updated_at = entry.get("nmap_updated_at", "")
                if nmap_raw :
                    return f"{nmap_raw}Last updated at: {nmap_updated_at}"
                else:
                    # If no Nmap data is found, run a new scan
                    print(f"Running Nmap scan for {ip} as no previous data found...")
                    nmap_raw, nmap_updated_at = run_nmap_raw(ip, data_file)
                    return f"{nmap_raw}Last updated at: {nmap_updated_at}"

        return "IP not found in the data file."

    except Exception as e:
        return f"❌ Error reading data file: {str(e)}"
    

def rerun_nmap_raw(ip, data_file):
    print(f"Re-running Nmap scan for {ip} ...")
    nmap_raw, nmap_updated_at = run_nmap_raw(ip, data_file)
    # make last updated text line without html
    return f"{nmap_raw} \n Last updated at: {nmap_updated_at}"