# ke-osint — Kenyan Entity OSINT Aggregator

> Passive recon tool scoped for Kenyan targets: `.ke` domains, local phone numbers, and regional social presence.

**Author:** hurricane597  
**Built for:** Authorized penetration testing, security assessments, and portfolio demonstration  
**Stack:** Python 3.8+, rich, dnspython, python-whois, requests

---

## Legal Disclaimer

This tool performs **passive, non-intrusive** reconnaissance only, there is no exploitation, active probing beyond standard HTTP requests and authentication bypass. You are solely responsible for ensuring you have authorization to investigate any target. Unauthorized OSINT activity may violate the Kenya Computer Misuse and Cybercrimes Act (2018) and other applicable laws.

---

## Installation

```bash
git clone https://github.com/yourusername/ke-osint
cd ke-osint
pip install -r requirements.txt
```

---

## Usage

```bash
# Domain recon (WHOIS, DNS, subdomains via crt.sh, reverse IP)
python main.py --target safaricom.co.ke --type domain

# Phone triage (carrier ID, breach check)
python main.py --target +254712345678 --type phone
python main.py --target 0712345678 --type phone

# Social footprint (username existence across 13 platforms)
python main.py --target johndoe --type social

# Email recon (MX check, disposable detection, HIBP)
python main.py --target user@company.co.ke --type email

# Print only, no saved report
python main.py --target example.co.ke --type domain --no-save

# Custom output directory
python main.py --target example.co.ke --type domain --output /tmp/reports
```

---

## Modules

| Module | Input | What it does |
|--------|-------|-------------|
| `domain` | Domain name | WHOIS, DNS records (A/MX/TXT/NS), reverse IP, subdomain enum via crt.sh |
| `phone` | KE phone number | Normalizes format, identifies carrier (Safaricom/Airtel/Telkom/Faiba), HIBP check |
| `social` | Username | Probes 13 platforms via HTTP — no API keys needed |
| `email` | Email address | Format validation, MX record check, disposable domain detection, HIBP lookup |

---

## Output

Each scan saves a structured JSON report to `output/`:

```
output/report_safaricom.co.ke_domain_20241201_143022.json
```

Report structure:
```json
{
  "tool": "ke-osint",
  "version": "1.0.0",
  "target": "safaricom.co.ke",
  "module": "domain",
  "timestamp": "2024-12-01T14:30:22Z",
  "findings": { ... }
}
```

---

## Project Structure

```
ke-osint/
├── main.py                  # CLI entry point
├── requirements.txt
├── README.md
├── LIMITATIONS.md           # Honest scope discussion
├── modules/
│   ├── domain_recon.py      # WHOIS, DNS, crt.sh, reverse IP
│   ├── phone_triage.py      # Carrier ID, HIBP
│   ├── social_footprint.py  # Username probing across 13 platforms
│   └── email_harvest.py     # MX, disposable check, HIBP
├── sample_report/
│   └── sample_domain_report.json   # Sanitized example output
└── output/                  # Generated reports (gitignored)
```

---

## Roadmap

- [ ] Combine multiple modules in a single scan (`--type all`)
- [ ] HIBP v3 API key integration for full email breach detail
- [ ] HTML report generation
- [ ] Google dork generator for `.ke` domains
- [ ] eCitizen business name lookup (web scraping)
