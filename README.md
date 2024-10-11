# easySub
easySub is a subdomain enumeration tool.

## Overview
```bash
    --------------------------------------
    |   easySub                          |
    |                                    |
    |    Author: G0urmetD                |
    |    Version: 1.1                    |
    --------------------------------------

usage: easySub.py [-h] [-d DOMAIN] [-p] [-hc HTTPCODE] [-o OUTPUT] [-ohttp] [-ohttps] [-u]

Subdomain Enumeration Script

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        The domain for which subdomains are to be enumerated.
  -p, --probe           Check subdomains for HTTP/HTTPS status codes.
  -hc HTTPCODE, --httpCode HTTPCODE
                        HTTP codes for filtering, separated by a comma (e.g. 200,401,403).
  -o OUTPUT, --output OUTPUT
                        Output file name. Specifies the file name to which the subdomains are to be exported.
  -ohttp                Schreibt die Subdomains in die Datei mit "http://" vor jeder Subdomain.
  -ohttps               Schreibt die Subdomains in die Datei mit "https://" vor jeder Subdomain.
  -u, --update          Switch parameter to update the tool.
```
