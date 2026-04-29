"""
Module: email_harvest
Email recon:
  - Format validation
  - Domain MX record check (is the domain actually receiving mail?)
  - HaveIBeenPwned breach lookup
  - Disposable email detection
"""

import re
import requests
import hashlib
import dns.resolver
from rich.table import Table
from rich import box
from rich.console import Console

# Common disposable email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "temp-mail.org", "throwam.com",
    "yopmail.com", "trashmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "guerrillamail.info", "spam4.me", "tempmail.com", "fakeinbox.com",
}


def validate_format(email: str) -> dict:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    valid = bool(re.match(pattern, email))
    parts = email.split("@") if "@" in email else [email, ""]
    return {
        "valid_format": valid,
        "local_part": parts[0],
        "domain": parts[1] if len(parts) > 1 else None,
    }


def check_mx(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted([(r.preference, str(r.exchange)) for r in answers])
        return {
            "has_mx": True,
            "mx_records": [f"{pref} {exc}" for pref, exc in mx_records],
            "primary_mx": mx_records[0][1] if mx_records else None,
            "confidence": "high",
        }
    except Exception as e:
        return {"has_mx": False, "error": str(e), "confidence": "low"}


def check_disposable(domain: str) -> dict:
    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    return {
        "is_disposable": is_disposable,
        "confidence": "high" if is_disposable else "medium",
        "note": "Known disposable domain" if is_disposable else "Not in disposable domain list",
    }


def check_hibp_email(email: str) -> dict:
    """Check HaveIBeenPwned for email breach appearances."""
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "User-Agent": "ke-osint/1.0",
            "hibp-api-key": "PUBLIC_CHECK",  # v3 requires API key for full results
        }
        resp = requests.get(url, timeout=10, headers=headers)
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "found": True,
                "breach_count": len(breaches),
                "breaches": [b.get("Name", "unknown") for b in breaches],
                "confidence": "high",
                "note": "HIBP v3 API key required for full results. Install: https://haveibeenpwned.com/API/Key",
            }
        elif resp.status_code == 404:
            return {"found": False, "breach_count": 0, "confidence": "high"}
        elif resp.status_code == 401:
            return {
                "found": None,
                "note": "HIBP v3 requires an API key. Add your key to modules/email_harvest.py",
                "confidence": "none",
            }
        else:
            return {"found": None, "status_code": resp.status_code, "confidence": "none"}
    except Exception as e:
        return {"error": str(e), "confidence": "none"}


def run_email_harvest(target: str, console: Console) -> dict:
    console.print(f"\n[bold cyan][ Email Harvest ][/bold cyan] → {target}\n")

    # Format validation
    fmt = validate_format(target)
    if not fmt["valid_format"]:
        console.print(f"[red]✗ Invalid email format: {target}[/red]")
        return {"error": "Invalid email format", "input": target}

    domain = fmt["domain"]
    console.print(f"  [dim]Local part:[/dim] {fmt['local_part']}  |  [dim]Domain:[/dim] {domain}\n")

    # Run checks
    console.print("[*] Checking MX records...")
    mx_data = check_mx(domain)

    console.print("[*] Checking disposable status...")
    disp_data = check_disposable(domain)

    console.print("[*] Querying HaveIBeenPwned...")
    hibp_data = check_hibp_email(target)

    # Display
    table = Table(box=box.SIMPLE_HEAVY, title="Email Recon Results", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Email", target)
    table.add_row("Domain", domain)
    table.add_row(
        "MX Records",
        "[green]Active[/green]" if mx_data.get("has_mx") else "[red]No MX — domain likely not receiving mail[/red]",
    )
    if mx_data.get("primary_mx"):
        table.add_row("Primary MX", mx_data["primary_mx"])
    table.add_row(
        "Disposable Domain",
        "[red]YES — likely throwaway[/red]" if disp_data["is_disposable"] else "[green]No[/green]",
    )

    if hibp_data.get("found") is True:
        table.add_row(
            "HIBP Breaches",
            f"[bold red]FOUND in {hibp_data['breach_count']} breach(es): {', '.join(hibp_data['breaches'][:5])}[/bold red]",
        )
    elif hibp_data.get("found") is False:
        table.add_row("HIBP Breaches", "[green]Not found[/green]")
    else:
        table.add_row("HIBP Breaches", f"[yellow]⚠ {hibp_data.get('note', 'Could not check')}[/yellow]")

    console.print(table)

    return {
        "email": target,
        "format": fmt,
        "mx": mx_data,
        "disposable": disp_data,
        "hibp": hibp_data,
    }
