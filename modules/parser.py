import re
import json
import unicodedata

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def remove_box_drawing(text):
    return ''.join(ch for ch in text if unicodedata.category(ch)[0] != 'C' and not unicodedata.name(ch, '').startswith("BOX DRAWINGS"))

def normalize_whitespace(text):
    lines = text.splitlines()
    cleaned_lines = [line.strip() for line in lines if line.strip()]
    return "\n".join(cleaned_lines)

def parse_nmap_output(text):
    text = remove_ansi_codes(text)
    text = remove_box_drawing(text)
    # Add newline before PORT headers if missing
    text = re.sub(r'(?<!\n)(PORT\s+STATE\s+SERVICE)', r'\n\1', text)
    text = normalize_whitespace(text)
    return text, {"lines": text.splitlines()}

def parse_metasploit_output(text):
    text = remove_ansi_codes(text)
    text = remove_box_drawing(text)
    text = normalize_whitespace(text)
    return text, {"lines": text.splitlines()}

def parse_netstat_output(text):
    text = remove_ansi_codes(text)
    text = remove_box_drawing(text)
    text = normalize_whitespace(text)
    return text, {"lines": text.splitlines()}

def write_outputs(base_name, cleaned_text, json_obj):
    with open(f"{base_name}.md", "w", encoding="utf-8") as f:
        f.write(cleaned_text)
    with open(f"{base_name}.json", "w", encoding="utf-8") as f:
        json.dump(json_obj, f, indent=4)
