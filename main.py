import time
from tqdm import tqdm
from modules.utils import get_sudo_password, create_output_dir
from modules.scanner import run_netstat, run_nmap, run_metasploit
from modules.parser import parse_scan_output, write_outputs


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
        print(f"\\n{task_name}")
    task_func()
    time.sleep(1)

print("[*] Parsing Nmap scan output...")
with open(f"{OUTPUT_DIR}/nmap_scan.txt", "r") as f:
    raw_nmap = f.read()

cleaned, structured = parse_scan_output(raw_nmap)
write_outputs(f"{OUTPUT_DIR}/parsed_nmap", cleaned, structured)


