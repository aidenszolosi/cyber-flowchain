# scanner.py
import subprocess

def run_netstat(output_path, sudo_password):
    command = f"echo {sudo_password} | sudo -S netstat -tulnp > {output_path}"
    subprocess.run(command, shell=True)

def run_nmap(output_path):
    command = f"nmap -p 1-1000 -T4 -A -v 127.0.0.1 > {output_path}"
    subprocess.run(command, shell=True)

def run_metasploit(output_path):
    command = (
        "msfconsole -q -x 'use auxiliary/scanner/smb/smb_version; "
        "set RHOSTS 127.0.0.1; run; exit' > " + output_path
    )
    subprocess.run(command, shell=True)
