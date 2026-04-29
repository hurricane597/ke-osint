"""
Module: phone_triage
Kenyan phone number triage:
  - Normalizes number format
  - Identifies carrier via prefix mapping
  - Checks HaveIBeenPwned for breach appearances
"""

import re
import requests
import hashlib
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.console import Console

# Kenyan carrier prefix mapping (first 6 digits after country code)
# Source: CA Kenya published number ranges
CARRIER_PREFIXES = {
    # Safaricom
    "0700": "Safaricom", "0701": "Safaricom", "0702": "Safaricom",
    "0703": "Safaricom", "0704": "Safaricom", "0705": "Safaricom",
    "0706": "Safaricom", "0707": "Safaricom", "0708": "Safaricom",
    "0709": "Safaricom", "0710": "Safaricom", "0711": "Safaricom",
    "0712": "Safaricom", "0713": "Safaricom", "0714": "Safaricom",
    "0715": "Safaricom", "0716": "Safaricom", "0717": "Safaricom",
    "0718": "Safaricom", "0719": "Safaricom", "0720": "Safaricom",
    "0721": "Safaricom", "0722": "Safaricom", "0723": "Safaricom",
    "0724": "Safaricom", "0725": "Safaricom", "0726": "Safaricom",
    "0727": "Safaricom", "0728": "Safaricom", "0729": "Safaricom",
    "0740": "Safaricom", "0741": "Safaricom", "0742": "Safaricom",
    "0743": "Safaricom", "0745": "Safaricom", "0746": "Safaricom",
    "0748": "Safaricom", "0757": "Safaricom", "0758": "Safaricom",
    "0759": "Safaricom", "0768": "Safaricom", "0769": "Safaricom",
    "0790": "Safaricom", "0791": "Safaricom", "0792": "Safaricom",
    "0793": "Safaricom", "0794": "Safaricom", "0795": "Safaricom",
    "0796": "Safaricom", "0797": "Safaricom", "0798": "Safaricom",
    "0799": "Safaricom",
    # Airtel Kenya
    "0730": "Airtel", "0731": "Airtel", "0732": "Airtel",
    "0733": "Airtel", "0734": "Airtel", "0735": "Airtel",
    "0736": "Airtel", "0737": "Airtel", "0738": "Airtel",
    "0739": "Airtel", "0750": "Airtel", "0751": "Airtel",
    "0752": "Airtel", "0753": "Airtel", "0754": "Airtel",
    "0755": "Airtel", "0756": "Airtel", "0762": "Airtel",
    "0763": "Airtel", "0764": "Airtel", "0765": "Airtel",
    "0766": "Airtel", "0767": "Airtel", "0768": "Airtel",
    # Telkom Kenya (Orange)
    "0770": "Telkom", "0771": "Telkom", "0772": "Telkom",
    "0773": "Telkom", "0774": "Telkom", "0775": "Telkom",
    "0776": "Telkom", "0777": "Telkom", "0778": "Telkom",
    "0779": "Telkom",
    # Faiba (JTL)
    "0747": "Faiba", "0769": "Faiba",
}


def normalize_number(raw: str) -> dict:
    """Normalize Kenyan phone number to 07XX and +2547XX formats."""
    cleaned = re.sub(r"[\s\-\(\)]", "", raw)
    local = None
    intl = None

    if cleaned.startswith("+254"):
        rest = cleaned[4:]
        local = "0" + rest
        intl = "+254" + rest
    elif cleaned.startswith("254"):
        rest = cleaned[3:]
        local = "0" + rest
        intl = "+254" + rest
    elif cleaned.startswith("07") or cleaned.startswith("01"):
        local = cleaned
        intl = "+254" + cleaned[1:]
    else:
        return {"error": f"Unrecognized format: {raw}", "valid": False}

    if len(local) != 10:
        return {"error": f"Invalid length ({len(local)} digits after normalization)", "valid": False}

    return {"local": local, "international": intl, "valid": True}


def identify_carrier(local: str) -> dict:
    prefix = local[:4]
    carrier = CARRIER_PREFIXES.get(prefix)
    if carrier:
        return {"carrier": carrier, "prefix": prefix, "confidence": "high"}
    return {"carrier": "Unknown", "prefix": prefix, "confidence": "low",
            "note": "Prefix not in current mapping — may be newly allocated"}


def check_hibp_phone(international: str) -> dict:
    """
    HIBP doesn't directly accept phone numbers, but we can search for the number
    as a string in the HIBP Pwned Passwords API (checks if it appears in breach data).
    This is a best-effort check — phone-specific breach DBs require paid APIs.
    """
    try:
        sha1 = hashlib.sha1(international.encode()).hexdigest().upper()
        prefix5 = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix5}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "ke-osint/1.0"})
        resp.raise_for_status()
        hashes = {line.split(":")[0]: int(line.split(":")[1]) for line in resp.text.splitlines()}
        if suffix in hashes:
            return {
                "found_in_breach_data": True,
                "occurrences": hashes[suffix],
                "note": "Number string appears in credential breach dumps",
                "confidence": "medium",
            }
        return {
            "found_in_breach_data": False,
            "occurrences": 0,
            "confidence": "medium",
            "note": "Not found in HIBP Pwned Passwords dataset",
        }
    except Exception as e:
        return {"error": str(e), "confidence": "none"}


def run_phone_triage(target: str, console: Console) -> dict:
    console.print(f"\n[bold cyan][ Phone Triage ][/bold cyan] → {target}\n")

    norm = normalize_number(target)
    if not norm.get("valid"):
        console.print(f"[red]✗ Normalization failed: {norm.get('error')}[/red]")
        return {"error": norm.get("error")}

    console.print(f"  [dim]Normalized:[/dim] {norm['local']} / {norm['international']}")

    carrier_data = identify_carrier(norm["local"])
    hibp_data = check_hibp_phone(norm["international"])

    table = Table(box=box.SIMPLE_HEAVY, show_header=False, title="Phone Triage Results")
    table.add_column("Field", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Local Format", norm["local"])
    table.add_row("International", norm["international"])
    table.add_row("Carrier", f"{carrier_data['carrier']} [{carrier_data['confidence']} confidence]")
    table.add_row("Prefix", carrier_data["prefix"])

    breach_val = (
        f"[red]YES — {hibp_data.get('occurrences', '?')} occurrences[/red]"
        if hibp_data.get("found_in_breach_data")
        else "[green]Not found[/green]"
    )
    table.add_row("HIBP Breach Check", breach_val)
    table.add_row("HIBP Note", hibp_data.get("note", "—"))

    console.print(table)

    if carrier_data.get("note"):
        console.print(f"[dim]  Note: {carrier_data['note']}[/dim]")

    return {
        "normalized": norm,
        "carrier": carrier_data,
        "hibp": hibp_data,
    }
