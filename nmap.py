import subprocess
import json
import os
def run_nmap_from_json_entry(entry):
    target = entry.get("domain") or (entry.get("ip")[0] if entry.get("ip") else None)

    if not target:
        print("No valid domain or IP found in entry.")
        return

    command = ["nmap", "--unprivileged", "-Pn", "-sV", "-p", "80,443", "--script", "ssl-cert", target]

    try:
        print(f"\nRunning Nmap scan on: {target}")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.stdout:
            print("Nmap Output:\n", result.stdout)
        if result.stderr:
            print("Nmap Errors:\n", result.stderr)
    except Exception as e:
        print(f"Error running Nmap: {e}")

def scan_selected_subdomains(file_path, indices_to_scan):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)

        for idx in indices_to_scan:
            if 0 <= idx < len(data):
                run_nmap_from_json_entry(data[idx])
            else:
                print(f"Index {idx} out of range.")

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        print(f"Invalid JSON file: {e}")

# === USAGE ===
# Path to your JSON file (update this as needed)


# Choose which subdomains to scan (by index)
indices_to_scan = [0, 3, 5]  # Example: scan entries at index 0, 3, and 5

# Run the scan
scan_selected_subdomains("data/iitm.ac.in_knockpy_results_with_certs.json", indices_to_scan)
