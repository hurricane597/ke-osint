#!/usr/bin/env python3
"""
ke-osint — Kenyan Entity OSINT Aggregator
Author: hurricane597
Usage: python main.py --target <domain|email|phone|username> --type <domain|phone|social|email>
"""

import argparse
import json
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from modules.domain_recon import run_domain_recon
from modules.phone_triage import run_phone_triage
from modules.social_footprint import run_social_footprint
from modules.email_harvest import run_email_harvest

console = Console()

BANNER = """
██╗  ██╗███████╗       ██████╗ ███████╗██╗███╗   ██╗████████╗
██║ ██╔╝██╔════╝      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
█████╔╝ █████╗  █████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██╔═██╗ ██╔══╝  ╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   
██║  ██╗███████╗      ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚═╝  ╚═╝╚══════╝       ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
  Kenyan Entity OSINT Aggregator | For authorized use only
"""

MODULE_MAP = {
    "domain": run_domain_recon,
    "phone": run_phone_triage,
    "social": run_social_footprint,
    "email": run_email_harvest,
}


def build_report(target: str, module: str, findings: dict) -> dict:
    return {
        "tool": "ke-osint",
        "version": "1.0.0",
        "target": target,
        "module": module,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
    }


def save_report(report: dict, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    safe_target = report["target"].replace("/", "_").replace(":", "_")
    filename = f"{output_dir}/report_{safe_target}_{report['module']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def main():
    console.print(Text(BANNER, style="bold green"))

    parser = argparse.ArgumentParser(
        description="ke-osint: Kenyan Entity OSINT Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target safaricom.co.ke --type domain
  python main.py --target +254712345678 --type phone
  python main.py --target johndoe --type social
  python main.py --target info@company.co.ke --type email
        """,
    )
    parser.add_argument("--target", required=True, help="Target to investigate")
    parser.add_argument(
        "--type",
        required=True,
        choices=MODULE_MAP.keys(),
        help="Recon module to run",
    )
    parser.add_argument(
        "--output", default="output", help="Output directory for reports (default: output/)"
    )
    parser.add_argument(
        "--no-save", action="store_true", help="Print results only, don't save report"
    )

    args = parser.parse_args()

    console.print(
        Panel(
            f"[bold]Target:[/bold] {args.target}\n[bold]Module:[/bold] {args.type}\n[bold]Time:[/bold] {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            title="[bold green]Scan Initiated",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    run_fn = MODULE_MAP[args.type]
    findings = run_fn(args.target, console)

    report = build_report(args.target, args.type, findings)

    if not args.no_save:
        path = save_report(report, args.output)
        console.print(f"\n[bold green]✓[/bold green] Report saved → [cyan]{path}[/cyan]")

    console.print("\n[bold green]✓ Scan complete.[/bold green]")


if __name__ == "__main__":
    main()
