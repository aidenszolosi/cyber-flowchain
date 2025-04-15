# Cyber Flowchain 🔐⚙️

An automated cybersecurity flowchain that runs multiple reconnaissance tools (Netstat, Nmap, Metasploit) and cleans their outputs for reporting and AI-based analysis. Built as part of a Capstone project at Columbus State Community College.

---

## 🧩 Features

- Modular Python script with clean separation of concerns
- Runs:
  - `netstat` for local port monitoring
  - `nmap` for remote port scanning
  - `metasploit` auxiliary modules for vulnerability checks
- Cleans and parses messy terminal output (removes color codes, box-drawing junk)
- Exports Markdown and JSON reports for each scan
- Ready for LLM integration in future phases (e.g., DeepSeek R1)

---

## 🛠️ Project Structure

```
cyber-flowchain/
├── main.py
├── modules/
│   ├── scanner.py      # Handles scan commands
│   ├── utils.py        # Directory + password helpers
│   └── parser.py       # Cleans and structures scan outputs
├── scan_results/       # All raw + parsed scan files go here
```

---

## 🚀 Getting Started

1. Clone the repo  
   ```bash
   git clone https://github.com/aidenszolosi/cyber-flowchain.git
   cd cyber-flowchain
   ```

2. Install dependencies (Python 3.8+ recommended)  
   ```bash
   pip install tqdm
   ```

3. Run the main script  
   ```bash
   python main.py
   ```

4. Enter your `sudo` password when prompted (required for `netstat`)

---

## 📂 Output Files

All output files are saved inside the `scan_results/` directory:

| File                    | Description                            |
|-------------------------|----------------------------------------|
| `netstat_output.txt`    | Raw output from netstat                |
| `nmap_scan.txt`         | Raw output from Nmap                   |
| `metasploit_scan.txt`   | Raw output from Metasploit auxiliary   |
| `parsed_*.md`           | Cleaned, readable version              |
| `parsed_*.json`         | Structured output for AI consumption   |

---

## 🧠 Future Plans (Phase 3+)

- Integrate DeepSeek R1 to summarize findings
- Generate human-readable vulnerability reports
- Add custom module selection + scan configuration
- Export to PDF or HTML

---

## 📜 License

MIT – do whatever you want with it, just credit when appropriate.

---

## 👤 Author

**Aiden Szolosi**  
Capstone Student – Columbus State Community College  
GitHub: [@aidenszolosi](https://github.com/aidenszolosi)
