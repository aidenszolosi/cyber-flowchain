# modules/parser.py

import re
import json

# Remove ANSI color codes (like from Metasploit)
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# Normalize line endings and remove excessive blank lines
def normalize_whitespace(text):
    lines = text.splitlines()
    cleaned_lines = [line.strip() for line in lines if line.strip()]
    return "\n".join(cleaned_lines)

# Convert cleaned text to structured JSON format (basic example)
def to_json(text):
    lines = text.splitlines()
    return {"lines": lines}

# Master parser function
def parse_scan_output(raw_text):
    clean = remove_ansi_codes(raw_text)
    normalized = normalize_whitespace(clean)
    return normalized, to_json(normalized)

# Write outputs to file
def write_outputs(base_name, cleaned_text, json_obj):
    with open(f"{base_name}.md", "w") as f:
        f.write(cleaned_text)

    with open(f"{base_name}.json", "w") as f:
        json.dump(json_obj, f, indent=4)
