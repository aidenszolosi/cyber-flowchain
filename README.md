# Cyber-Flowchain 🛡️📡  
**Pure-Python recon + AI reporting, powered by `uv`**

A **single-file**, cross-platform cybersecurity TUI that…

* performs host discovery, TCP connect-scans, banner grabs, HTTP probing, TLS-certificate peeking and legacy-TLS tests — **no Kali, no Nmap, no OpenSSL CLI**  
* streams a YAML snapshot to a local **DeepSeek R1** model (via Ollama) and renders the AI’s executive summary live in your terminal  
* stores every run under `flowchain_outputs/` for later auditing  

The project now uses **`uv`** (a super-fast Rust replacement for pip + virtualenv) for reproducible, lightning-quick installs.

---

## ✨ Features

| Module                | Details (Python-only)                                  |
|-----------------------|--------------------------------------------------------|
| Ping sweep            | Optional via `pythonping`                              |
| TCP connect-scan      | 200-thread multiscanner                                |
| Service fingerprint   | IANA names for every open port                         |
| Banner grab           | First 128 B greeting                                   |
| HTTP probe            | `Server` header + HTML `<title>`                       |
| TLS peek              | CN / issuer / expiry via `cryptography`                |
| Legacy TLS detection  | Attempts TLS 1.0 / 1.1 handshakes                      |
| Fallback wide scan    | Auto-scans ports 1-1024 if nothing found on user list  |
| AI summary            | Streams tokens from DeepSeek R1 via Ollama             |

---

## 📦 Quick start (with **uv**)

> **Prerequisites**  
> – Python 3.10+  
> – [Ollama](https://ollama.com/) with DeepSeek R1 (`ollama pull deepseek-r1:14b`)  
> – A recent `uv` binary  

```bash
# Install uv (macOS/Linux)
curl -Ls https://astral.sh/uv/install.sh | sh
# Windows → winget install astral.uv

git clone https://github.com/yourname/cyber-flowchain.git
cd cyber-flowchain

uv venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

uv pip install -r requirements.txt   # milliseconds!

# in another terminal
ollama serve                         # http://localhost:11434

uv run main.py
```

---

## 🚀 Example run

```
Targets (comma/CIDR) [127.0.0.1]: scanme.nmap.org
Ping sweep first? (y/n) [y]:
Grab banners? (y/n) [y]:
AI executive summary? (y/n) [y]:

── Port scanning
✓ scanme.nmap.org  →  22/tcp  80/tcp

── 🤖 DeepSeek R1 stream 🤖
• SSH 22: OpenSSH 6.6p1 (EOL)  
• HTTP 80: Apache 2.4.7 default page  
Risk = **Medium** …
```

Artifacts:

```
flowchain_outputs/
└── 20250424T174500Z/
    ├── snapshot.yaml   # structured findings
    └── summary.md      # AI narrative
```

---

## 🔧 Project layout

```
.
├── main.py            ← ~400 LOC TUI
├── requirements.txt   ← deps for uv pip
└── README.md
```

---

## 🛠️  Dev tips (uv)

| Task                         | Command                                  |
|------------------------------|------------------------------------------|
| Add dependency               | `uv pip install rich`                    |
| Run pytest                   | `uv pip install pytest` → `uv run -m pytest` |
| Sync env from lockfile       | `uv pip sync`                            |
| Upgrade deps                 | `uv pip install --upgrade -r requirements.txt` |

`uv` stores a deterministic lockfile in `.venv/packages.lock.toml`.

---

