# easySub
easySub is a subdomain enumeration tool.

# Usage
```bash
# basic usage possibilities
python3 easySub.py -d target.domain                          # basic subdomain enumeration with cli output
python3 easySub.py -d target.domain -api                     # extended subdomain enumeration with api key sources with cli output
python3 easySub.py -d target.domain -p                       # basic subdomain enumeration with cli output & HTTP/HTTPS probe
python3 easySub.py -d target.domain -p -hc 200,403           # basic subdomain enumeration with cli output & HTTP/HTTPS probe & filter for HTTP codes

# output possibilities
python3 easySub.py -d target.domain -o output.txt            # prints subdoamins into output file
python3 easySub.py -d target.domain -o output.txt -ohttp     # prints string 'http://' in front of every subdomain in output file
python3 easySub.py -d target.domain -o output.txt -ohttps    # prints string 'https://' in front of every subdomain in output file

# some examples
python3 easySub.py -d target.domain -api -p -hc 200 -o target.txt -ohttps
python3 easySub.py -d target.domain -api -p -hc 200 -o target.txt -ohttp
```

## Overview
```bash
    --------------------------------------
    |   easySub                          |
    |                                    |
    |    Author: G0urmetD                |
    |    Version: 1.2.2                  |
    --------------------------------------

usage: easySub.py [-h] [-d DOMAIN] [-p] [-hc HTTPCODE] [-o OUTPUT] [-ohttp] [-ohttps] [-u] [-api]

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
  -ohttp                Adds string in front of every subdomain: http://.
  -ohttps               Adds string in front of every subdomain: https://
  -u, --update          Switch parameter to update the tool.
  -api                  Include sources that require API keys (configure in config.json).
```
