"""
Module: domain_recon
Performs passive recon on a target domain:
  - WHOIS lookup
  - DNS records (A, MX, TXT, NS)
  - Subdomain enumeration via crt.sh certificate transparency
"""

import socket
import requests
##import whois
import dns.resolver
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.console import Console


def whois_lookup(domain: str) -> dict:
    try:
        import subprocess, re
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        raw = result.stdout

        def extract(pattern):
            m = re.search(pattern, raw, re.IGNORECASE)
            return m.group(1).strip() if m else None

        return {
            "registrar": extract(r"Registrar:\s*(.+)"),
            "creation_date": extract(r"Creation Date:\s*(.+)"),
            "expiration_date": extract(r"Expir\w+ Date:\s*(.+)"),
            "name_servers": re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE),
            "status": extract(r"Domain Status:\s*(.+)"),
            "emails": list(set(re.findall(r"[\w.+-]+@[\w.-]+\.\w+", raw))),
            "org": extract(r"Registrant Organization:\s*(.+)"),
            "country": extract(r"Registrant Country:\s*(.+)"),
            "confidence": "high" if raw.strip() else "none",
        }
    except Exception as e:
        return {"error": str(e), "confidence": "none"}


def dns_records(domain: str) -> dict:
    results = {}
    record_types = ["A", "MX", "TXT", "NS", "AAAA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []
    results["confidence"] = "high" if results.get("A") else "low"
    return results


def crtsh_subdomains(domain: str) -> dict:
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        entries = resp.json()
        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
        return {
            "count": len(subdomains),
            "subdomains": sorted(subdomains),
            "confidence": "high" if subdomains else "low",
        }
    except Exception as e:
        return {"error": str(e), "count": 0, "subdomains": [], "confidence": "none"}


def reverse_ip(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "reverse_hostname": hostname, "confidence": "high"}
    except Exception as e:
        return {"error": str(e), "confidence": "none"}


def run_domain_recon(target: str, console: Console) -> dict:
    console.print(f"\n[bold cyan][ Domain Recon ][/bold cyan] → {target}\n")

    # --- WHOIS ---
    console.print("[*] Running WHOIS lookup...")
    whois_data = whois_lookup(target)

    whois_table = Table(title="WHOIS", box=box.SIMPLE_HEAVY, show_header=False)
    whois_table.add_column("Field", style="bold")
    whois_table.add_column("Value", style="green")
    for k, v in whois_data.items():
        if k == "confidence":
            continue
        display = ", ".join(v) if isinstance(v, list) else str(v) if v else "—"
        whois_table.add_row(k.replace("_", " ").title(), display)
    console.print(whois_table)

    # --- DNS ---
    console.print("[*] Resolving DNS records...")
    dns_data = dns_records(target)

    dns_table = Table(title="DNS Records", box=box.SIMPLE_HEAVY, show_header=False)
    dns_table.add_column("Type", style="bold")
    dns_table.add_column("Records", style="green")
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        records = dns_data.get(rtype, [])
        display = "\n".join(records) if records else "—"
        dns_table.add_row(rtype, display)
    console.print(dns_table)

    # --- Reverse IP ---
    console.print("[*] Checking reverse IP...")
    rev_data = reverse_ip(target)
    console.print(
        Panel(
            f"IP: [green]{rev_data.get('ip', 'N/A')}[/green]  |  Reverse: [green]{rev_data.get('reverse_hostname', 'N/A')}[/green]",
            title="Reverse IP",
            border_style="dim",
            box=box.SIMPLE,
        )
    )

    # --- crt.sh ---
    console.print("[*] Enumerating subdomains via crt.sh (certificate transparency)...")
    crt_data = crtsh_subdomains(target)

    if crt_data.get("subdomains"):
        sub_table = Table(
            title=f"Subdomains ({crt_data['count']} found)",
            box=box.SIMPLE_HEAVY,
            show_header=False,
        )
        sub_table.add_column("Subdomain", style="green")
        for sub in crt_data["subdomains"][:30]:  # cap display at 30
            sub_table.add_row(sub)
        if crt_data["count"] > 30:
            sub_table.add_row(f"... and {crt_data['count'] - 30} more (see report JSON)")
        console.print(sub_table)
    else:
        console.print("[dim]  No subdomains found via crt.sh[/dim]")

    return {
        "whois": whois_data,
        "dns": dns_data,
        "reverse_ip": rev_data,
        "subdomains_crtsh": crt_data,
    }
