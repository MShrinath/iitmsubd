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

            now_ist = datetime.now().isoformat() + "Z"  # ISO format with UTC timezone

            for entry in data:
                if target in entry.get("ip", []):
                    entry["nmap"] = output
                    entry["nmap_updated_at"] = now_ist

            with open(save_path, "w") as f:
                json.dump(data, f, indent=4)
            print(f"✅ Appended Nmap output to {target} in {save_path}")

        except Exception as e:
            print(f"❌ Error updating JSON file: {e}")

        return output

    except subprocess.CalledProcessError as e:
        return f"❌ Nmap scan failed!\n---\nError Output:\n{e.stderr or str(e)}\n---"
    except Exception as e:
        return f"❌ Unexpected error during Nmap scan!\n---\nDetails: {str(e)}\n---"
