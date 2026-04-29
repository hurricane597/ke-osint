"""
Module: social_footprint
Checks username existence across social platforms via HTTP response probing.
No APIs required — uses response codes, redirects, and page content signals.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich import box
from rich.console import Console

# Platform definitions: url template + detection method
# Methods: status_code (200 = found), redirect (no redirect = found), content (string in body = found)
PLATFORMS = {
    "Twitter/X": {
        "url": "https://x.com/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "GitHub": {
        "url": "https://github.com/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "method": "content",
        "found_string": '"page_id"',
        "not_found_string": "Sorry, this page",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}/",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}/",
        "method": "content",
        "found_string": '"is_suspended": false',
        "not_found_string": "page not found",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "HackTheBox": {
        "url": "https://app.hackthebox.com/users/profile/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "TryHackMe": {
        "url": "https://tryhackme.com/p/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "method": "status_code",
        "found_code": 200,
        "not_found_code": 404,
    },
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


def check_platform(platform: str, config: dict, username: str) -> dict:
    url = config["url"].format(username=username)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        method = config["method"]

        if method == "status_code":
            found = resp.status_code == config["found_code"]
        elif method == "content":
            body = resp.text.lower()
            found_str = config.get("found_string", "").lower()
            not_found_str = config.get("not_found_string", "").lower()
            found = found_str in body and not_found_str not in body
        else:
            found = False

        return {
            "platform": platform,
            "url": url,
            "found": found,
            "status_code": resp.status_code,
            "confidence": "medium",
        }
    except requests.exceptions.Timeout:
        return {"platform": platform, "url": url, "found": None, "error": "timeout", "confidence": "none"}
    except Exception as e:
        return {"platform": platform, "url": url, "found": None, "error": str(e), "confidence": "none"}


def run_social_footprint(target: str, console: Console) -> dict:
    console.print(f"\n[bold cyan][ Social Footprint ][/bold cyan] → @{target}\n")
    console.print(f"[*] Probing {len(PLATFORMS)} platforms (parallel)...\n")

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_platform, name, cfg, target): name
            for name, cfg in PLATFORMS.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: (x["found"] is None, not x.get("found", False), x["platform"]))

    found = [r for r in results if r.get("found") is True]
    not_found = [r for r in results if r.get("found") is False]
    errors = [r for r in results if r.get("found") is None]

    table = Table(box=box.SIMPLE_HEAVY, title=f"Social Footprint: {target}")
    table.add_column("Platform", style="bold")
    table.add_column("Status")
    table.add_column("URL", style="dim")

    for r in results:
        if r.get("found") is True:
            status = "[bold green]✓ FOUND[/bold green]"
        elif r.get("found") is False:
            status = "[dim]✗ not found[/dim]"
        else:
            status = f"[yellow]⚠ {r.get('error', 'error')}[/yellow]"
        table.add_row(r["platform"], status, r["url"])

    console.print(table)
    console.print(
        f"\n  [bold green]{len(found)} found[/bold green] | "
        f"[dim]{len(not_found)} not found[/dim] | "
        f"[yellow]{len(errors)} errors[/yellow]"
    )

    if found:
        console.print("\n[bold]Confirmed accounts:[/bold]")
        for r in found:
            console.print(f"  [green]→[/green] {r['platform']}: {r['url']}")

    return {
        "username": target,
        "platforms_checked": len(PLATFORMS),
        "found_count": len(found),
        "results": results,
    }
