# utils.py
import os
import getpass

def get_sudo_password():
    return getpass.getpass("🔐 Enter your sudo password: ")

def create_output_dir(dir_name="scan_results"):
    os.makedirs(dir_name, exist_ok=True)
    return dir_name
