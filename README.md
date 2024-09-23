# easySub
easySub is a subdomain enumeration tool.

## Overview
```bash
    --------------------------------------
    |   easySub                          |
    |                                    |
    |    Author: G0urmetD                |
    |    Version: 1.0                    |
    --------------------------------------

usage: easySub.py [-h] -d DOMAIN [-p] [-hc HTTPCODE] [-o OUTPUT] [-of {http,https}] [-u]

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
  -of {http,https}, --filteroutput {http,https}
                        Filter method for the output. Add either ‘http://’ or ‘https://’ in front of the subdomains.
  -u, --update          Switch parameter to update the tool. # not implemented yet
```
