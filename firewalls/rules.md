## Firewall Rules for Cloudflare

Recommended firewall rules to protect a web site exposed via Cloudflare Tunnel.

Overview of rules
-----------------
- Bad Bot — Block
- Exploiting Fix — Block
- Method Fix (Optional) — Block
- Threat Check (Optional) — Challenge

# Bad Bot — Action: Block
------------------------
Block known malicious user agents, suspicious port usage, old HTTP versions, invalid HTTP methods, suspicious X-Forwarded-For headers, Tor network traffic, scraping ASNs, and non-standard cookies.

Example conditions:
- User Agent matches known bad bot signatures
- Request port matches unusual ports
- HTTP version equals 1.0
- Request method not in [GET,POST,PUT,DELETE,HEAD,OPTIONS]
- X-Forwarded-For matches suspicious patterns
- ASN in list of scraping ASNs
- Cookie header has non-standard format

# Exploiting Fix — Action: Block
------------------------------
Block obvious exploitation attempts such as SQL injection patterns, XSS payloads, and common PHP exploitation signatures.

Example conditions:
- URI contains SQL meta-characters or common SQL injection patterns
- Request body or query contains XSS-like script tags
- Patterns indicating PHP vulnerability exploitation

# Method Fix (Optional) — Action: Block
------------------------------------
Block unusual or unexpected HTTP methods used in attacks (e.g., PROPFIND, TRACK).

Example conditions:
- HTTP method in [PROPFIND, TRACK, CONNECT, TRACE] (adjust as needed)

# Threat Check (Optional) — Action: Challenge
-------------------------------------------
Challenge requests based on additional heuristics such as old HTTP versions, requests without TLS, or missing Referer header.

Example conditions:
- HTTP version in [1.1, 1.2]
- Request is not over TLS
- Referer header is empty or missing

![Example](/img/example.png)

Credits
-------
Firewall rule by SocolSRT.
