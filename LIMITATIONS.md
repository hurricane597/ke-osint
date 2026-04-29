# LIMITATIONS.md — Honest Scope Discussion

### What it does well

- **Domain recon** is reliable. WHOIS, DNS, and crt.sh are open data, the results are accurate and complete for most `.ke` domains.
- **Subdomain enumeration** via certificate transparency is passive and legitimate but only surfaces domains that have had TLS certificates issued. Private/internal subdomains won't appear.
- **Phone carrier identification** is accurate for standard allocations but the CA Kenya number range database isn't publicly versioned so newly allocated prefixes may not be mapped.
- **Social footprint** is best-effort. Platforms frequently change their HTTP response behavior to block automated requests. A "not found" result could be a block, not genuine absence. Instagram and LinkedIn are the least reliable due to aggressive bot detection.
- **HIBP email check** requires a paid API key (v3) for reliable results. The implementation is structured correctly — it just needs a key added.

### What it cannot do

- **Verify phone number is active** carrier ID doesn't confirm the number is in use or registered to a specific person.
- **Access private data** M-Pesa transaction history, eCitizen records, Huduma Namba data, and court records all require authenticated access or formal legal process.
- **Confirm social account identity** finding a username on multiple platforms doesn't confirm they belong to the same person without corroborating evidence.
- **SMTP validation** confirming an email address actually exists requires an SMTP handshake, which is outside passive recon scope and may violate mail server terms of service.
- **Real-time data** crt.sh may lag by hours; WHOIS data can be stale if a registrar caches updates.

### Rate limiting and detection

Running this tool frequently against the same target, or running the social footprint module at high concurrency, may trigger rate limiting or IP blocks from target platforms. The tool is designed for single investigative use, not automated bulk scanning.

### Legal scope

ke-osint performs no:
- Authentication bypass
- Injection or exploitation
- Unauthorized account access
- Traffic interception

All data sources queried are publicly accessible. Authorization to investigate a target is your responsibility.
