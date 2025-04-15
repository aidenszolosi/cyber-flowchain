import time
from tqdm import tqdm
from modules.utils import get_sudo_password, create_output_dir
from modules.scanner import run_netstat, run_nmap, run_metasploit
from modules.parser import (
    parse_nmap_output,
    parse_metasploit_output,
    parse_netstat_output,
    write_outputs,
)

DEBUG = False
OUTPUT_DIR = create_output_dir()
sudo_password = get_sudo_password()

tasks = [
    ("Running Netstat...", lambda: run_netstat(f"{OUTPUT_DIR}/netstat_output.txt", sudo_password)),
    ("Running Nmap scan...", lambda: run_nmap(f"{OUTPUT_DIR}/nmap_scan.txt")),
    ("Running Metasploit scan...", lambda: run_metasploit(f"{OUTPUT_DIR}/metasploit_scan.txt"))
]

for task_name, task_func in tqdm(tasks, desc="Scanning Progress", unit="task"):
    if DEBUG:
        print(f"\n{task_name}")
    task_func()
    time.sleep(1)

# ---- Parse Outputs ----
print("[*] Parsing Netstat scan...")
with open(f"{OUTPUT_DIR}/netstat_output.txt", "r", encoding="utf-8") as f:
    netstat_raw = f.read()
clean_netstat, json_netstat = parse_netstat_output(netstat_raw)
write_outputs(f"{OUTPUT_DIR}/parsed_netstat", clean_netstat, json_netstat)

print("[*] Parsing Nmap scan...")
with open(f"{OUTPUT_DIR}/nmap_scan.txt", "r", encoding="utf-8") as f:
    nmap_raw = f.read()
clean_nmap, json_nmap = parse_nmap_output(nmap_raw)
write_outputs(f"{OUTPUT_DIR}/parsed_nmap", clean_nmap, json_nmap)

print("[*] Parsing Metasploit scan...")
with open(f"{OUTPUT_DIR}/metasploit_scan.txt", "r", encoding="utf-8") as f:
    msf_raw = f.read()
clean_msf, json_msf = parse_metasploit_output(msf_raw)
write_outputs(f"{OUTPUT_DIR}/parsed_msf", clean_msf, json_msf)
