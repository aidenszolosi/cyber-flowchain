#!/usr/bin/env python3
# main.py – Cyber-Flowchain all-in-one TUI (with fallback wide scan + legacy-TLS check)
# pure-python, scroll-friendly, DeepSeek-ready
from __future__ import annotations

import ipaddress, json, platform, ssl, socket, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psutil, requests, yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

try:
    from pythonping import ping  # type: ignore
except Exception:
    ping = None

console  = Console(highlight=False)
TS       = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
OUTDIR   = Path("flowchain_outputs") / TS
MODEL    = "deepseek-r1:14b"

# ───────────────────────── helpers ─────────────────────────
def _save(p: Path, data: str | bytes, bin: bool = False) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb" if bin else "w", encoding=None if bin else "utf-8") as f:
        f.write(data)

def system_snapshot() -> Dict[str, Any]:
    u = platform.uname(); vm = psutil.virtual_memory()
    return {"hostname": u.node, "os": f"{u.system} {u.release}",
            "cpu_cores": psutil.cpu_count(True), "memory_mb": round(vm.total / 1024**2)}

# ───────── ping / TCP connect ─────────
def host_alive(h: str, to: float = 1.0) -> bool:
    if ping is None: return True
    try: return ping(h, count=1, timeout=to, verbose=False).success()
    except Exception: return False

def _tcp(h: str, p: int, to: float = 1.0) -> Tuple[int, bool]:
    try:
        with socket.create_connection((h, p), to): return p, True
    except Exception: return p, False

def connect_scan(h: str, ports: Iterable[int]) -> Dict[str, Any]:
    results: Dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=200) as pool:
        futs = {pool.submit(_tcp, h, p): p for p in ports}
        for f in as_completed(futs):
            port, ok = f.result(); results[port] = ok
    return {"host": h, "open_ports": [p for p, ok in sorted(results.items()) if ok]}

# ───────── banner / HTTP probe ─────────
def grab_banner(h: str, p: int, to: float = 2.0) -> str:
    try:
        with socket.create_connection((h, p), to) as s:
            s.settimeout(to)
            if p in {80, 8080, 8000, 443}:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            return s.recv(128).decode(errors="ignore").replace("\r", " ").replace("\n", " | ")
    except Exception:
        return ""

class _TitleParser(HTMLParser):
    def __init__(self): super().__init__(); self._in=False; self.title=""
    def handle_starttag(self, tag, attrs): self._in = tag.lower() == "title"
    def handle_endtag(self, tag): self._in = False if tag.lower() == "title" else self._in
    def handle_data(self, data): self.title += data.strip() if self._in else ""

def http_probe(h: str, p: int, tls=False, to: float = 3.0) -> Dict[str, str]:
    scheme = "https" if tls else "http"
    try:
        r = requests.get(f"{scheme}://{h}:{p}", timeout=to, verify=False)
        parser = _TitleParser(); parser.feed(r.text[:4096])
        return {"server": r.headers.get("Server", ""), "title": parser.title[:120]}
    except Exception:
        return {}

# ───────── TLS cert + legacy version test ─────────
def tls_cert(h: str, p: int, to: float = 3.0) -> Optional[Dict[str, str]]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=h) as s:
            s.settimeout(to); s.connect((h, p)); der = s.getpeercert(True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        return {"subject": cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)[0].value,
                "issuer":  cert.issuer.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)[0].value,
                "not_after": cert.not_valid_after.isoformat()}
    except Exception:
        return None

def legacy_tls(h: str, p: int, to: float = 3.0) -> List[str]:
    insecure = []
    for ver, proto in [("TLSv1", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(proto); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=h) as s:
                s.settimeout(to); s.connect((h, p))
            insecure.append(ver)
        except Exception:
            pass
    return insecure

# ───────── DeepSeek stream ─────────
def stream_deepseek(yaml_blob: str):
    payload = {
        "model": MODEL,
        "prompt": (
            "You are a cybersecurity analyst. Using the YAML below, highlight risky services, "
            "dangerous banners, legacy TLS versions, expired certs, and give brief remediation.\n\n"
            + yaml_blob
        ),
        "stream": True,
    }
    try:
        with requests.post("http://localhost:11434/api/generate",
                           json=payload, stream=True, timeout=120) as r:
            r.raise_for_status()
            for ln in r.iter_lines(decode_unicode=True):
                if ln:
                    try: chunk = json.loads(ln)
                    except json.JSONDecodeError: continue
                    yield chunk.get("response", ""), chunk.get("done", False)
    except Exception as e:
        yield f"[LLM-ERROR] {e}", True

# ───────── input prompts ─────────
def expand_targets(raw: List[str]) -> Iterable[str]:
    for item in raw:
        try:
            for ip in ipaddress.ip_network(item, strict=False).hosts():
                yield str(ip)
        except ValueError:
            yield item

def get_opts() -> Dict[str, Any]:
    console.print(Panel("[bold cyan]Cyber-Flowchain[/bold cyan]", box=box.ROUNDED))
    tgt = Prompt.ask("Targets (comma/CIDR)", default="127.0.0.1")
    targets = [t.strip() for t in tgt.split(",") if t.strip()]
    if Confirm.ask("Scan port range?", default=False):
        start = int(Prompt.ask("Start", default="1"))
        end   = int(Prompt.ask("End",   default="1024"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in Prompt.ask("Ports", default="22,80,443").split(",") if p.isdigit()]
    return {
        "targets": targets,
        "ports": ports,
        "ping": ping is not None and Confirm.ask("Ping sweep first?", default=True),
        "banners": Confirm.ask("Grab banners?", default=True),
        "ai": Confirm.ask("AI executive summary?", default=True),
    }

# ───────── main workflow ─────────
def run(cfg: Dict[str, Any]):
    console.rule("[cyan]Local system info"); local = system_snapshot()
    targets = list(expand_targets(cfg["targets"]))

    # ping sweep
    if cfg["ping"]:
        console.rule("[cyan]Ping sweep")
        alive = []
        with Progress(SpinnerColumn(), "{task.description}", TimeElapsedColumn(), console=console) as prog:
            tid = prog.add_task("Pinging", total=len(targets))
            for h in targets:
                if host_alive(h): alive.append(h)
                prog.advance(tid)
        targets = alive or targets

    # scan pass (function so we can call twice)
    def do_scan(port_set: Iterable[int]) -> List[Dict[str, Any]]:
        scans = []
        with Progress(SpinnerColumn(), "{task.description}", TimeElapsedColumn(), console=console) as prog:
            tid = prog.add_task("Scanning", total=len(targets))
            for host in targets:
                res = connect_scan(host, port_set)
                try: res["ptr"] = socket.gethostbyaddr(host)[0]
                except Exception: res["ptr"] = ""

                res["services"] = {p: (socket.getservbyport(p, "tcp") if p < 65536 else "")
                                   for p in res["open_ports"]}
                res["banners"]  = {}; res["http"] = {}; res["tls_cert"] = {}; res["tls_legacy"] = {}
                for p in res["open_ports"]:
                    if cfg["banners"]:
                        res["banners"][str(p)] = grab_banner(host, p) or "-"
                    if p in {80, 8080, 8000}:  # HTTP
                        res["http"][str(p)] = http_probe(host, p, tls=False)
                    if p in {443, 8443, 9443}:  # HTTPS
                        res["http"][str(p)] = http_probe(host, p, tls=True)
                        cert = tls_cert(host, p)
                        if cert: res["tls_cert"][str(p)] = cert
                        legacy = legacy_tls(host, p)
                        if legacy: res["tls_legacy"][str(p)] = legacy
                scans.append(res); prog.advance(tid)
        return scans

    scans = do_scan(cfg["ports"])
    if all(not s["open_ports"] for s in scans):
        console.print("[yellow]No open ports found – rescanning 1-1024…[/yellow]")
        scans = do_scan(range(1, 1025))

    # snapshot
    snap = {"generated": TS, "local": local, "scans": scans}
    OUTDIR.mkdir(parents=True, exist_ok=True)
    yaml_blob = yaml.safe_dump(snap, sort_keys=False)
    _save(OUTDIR / "snapshot.yaml", yaml_blob)
    console.print(f"[green]Saved snapshot → {OUTDIR/'snapshot.yaml'}")

    # DeepSeek
    ai_text = ""
    if cfg["ai"]:
        console.rule("[cyan]🤖 DeepSeek R1 stream 🤖")
        console.print(Panel("🟢 generating executive summary…", border_style="cyan"))
        buf, inside = "", False
        for tok, done in stream_deepseek(yaml_blob):
            if "<think>" in tok: inside = True; continue
            if "</think>" in tok: inside = False; continue
            if inside or not tok: continue
            ai_text += tok; buf += tok
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                console.print(Markdown(line)) if line.strip() else console.print()
            sys.stdout.flush()
            if done: break
        if buf.strip(): console.print(Markdown(buf))
        _save(OUTDIR / "summary.md", ai_text)
        console.rule("[green]📄 Executive Summary[/green]")
        console.print(Panel(Markdown(ai_text), border_style="bright_green", box=box.ROUNDED))

    show_results(scans)

# ───────── results table ─────────
def show_results(scans: List[Dict[str, Any]]):
    tbl = Table(title="Scan results", box=box.MINIMAL_DOUBLE_HEAD, show_lines=True)
    tbl.add_column("Host", style="cyan")
    tbl.add_column("Port", style="green")
    tbl.add_column("Svc",  style="magenta")
    tbl.add_column("Banner / Title", style="yellow", overflow="fold")
    for s in scans:
        for p in s["open_ports"]:
            svc = s["services"].get(p, "")
            banner = s["banners"].get(str(p), "-")
            title  = s.get("http", {}).get(str(p), {}).get("title", "")
            cell   = banner if banner != "-" else (title or "-")
            tbl.add_row(s["host"], str(p), svc, cell)
    console.rule("[cyan]Results"); console.print(tbl)

# ───────── entrypoint ─────────
if __name__ == "__main__":
    try: run(get_opts())
    except KeyboardInterrupt:
        console.print("\n[red]Cancelled by user[/red]"); sys.exit(1)
