import os
import subprocess
import time
import zipfile
import getpass
from tqdm import tqdm

# Enable/Disable Debug Mode
debug = False  # Set to False for silent mode

# Get sudo password once
sudo_password = getpass.getpass("🔐 Enter your sudo password: ")

# Create directory to store scan results
OUTPUT_DIR = "scan_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define scanning tasks
tasks = [
    ("Running Netstat...", f"echo {sudo_password} | sudo -S netstat -tulnp > {OUTPUT_DIR}/netstat_output.txt"),
    ("Running Nmap scan...", f"nmap -p 1-1000 -T4 -A -v 127.0.0.1 > {OUTPUT_DIR}/nmap_scan.txt"),
    ("Running Metasploit scan...", f"msfconsole -q -x 'use auxiliary/scanner/smb/smb_version; set RHOSTS 127.0.0.1; run; exit' > {OUTPUT_DIR}/metasploit_scan.txt")
]

# Run tasks with a progress bar
for task_name, command in tqdm(tasks, desc="Scanning Progress", unit="task"):
    if debug:
        print(f"\n{task_name}")  # Only print task name if debug mode is enabled
    time.sleep(1)  # Simulating delay for realism
    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL if not debug else None)

print("\n✅ Scanning complete! Results saved in 'scan_results' directory.")

# Ask if the user wants to create a ZIP archive of the results
create_zip = input("\n📦 Do you want to create a ZIP file of the scan results? (y/n): ").strip().lower()

if create_zip == "y":
    zip_filename = os.path.join(OUTPUT_DIR, "scan_results.zip")
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in os.listdir(OUTPUT_DIR):
            if file.endswith(".txt"):  # Only add text files
                zipf.write(os.path.join(OUTPUT_DIR, file), file)
    
    print(f"\n📁 ZIP file created: {zip_filename}")
else:
    print("\n❌ Skipping ZIP file creation.")

print("\n🎯 Phase 1 completed successfully!")
