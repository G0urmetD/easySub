import os
import re
import json
import argparse
import requests
from colorama import Fore, Style, init
from update_checker import check_for_updates
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def load_config():
    with open("config.json") as config_file:
        return json.load(config_file)

config = load_config()
CURRENT_VERSION = config["version"]

def print_banner():
    banner = f"""{Fore.MAGENTA}
    --------------------------------------
    |   easySub                          |
    |                                    |
    |    Author: G0urmetD                |
    |    Version: {CURRENT_VERSION}                    |
    --------------------------------------
    {Style.RESET_ALL}"""
    print(banner)

def load_api_keys(config_file='config.json'):
    """
    Loads API keys from a JSON config file.
    """
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            api_keys = config.get("api_keys", {})
            return api_keys
    except FileNotFoundError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Config file '{config_file}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error decoding JSON in '{config_file}'.")
        return {}

def enumerate_subdomains(domain, use_api=False):
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(enumerate_subdomains_crtsh, domain),
            executor.submit(enumerate_subdomains_hackertarget, domain),
            executor.submit(enumerate_subdomains_threatcrowd, domain),
            executor.submit(enumerate_subdomains_certspotter, domain),
            executor.submit(enumerate_subdomains_anubis, domain)
        ]

        if use_api:
            api_keys = load_api_keys()
            if api_keys.get("securitytrails_api_key"):
                futures.append(executor.submit(enumerate_subdomains_securitytrails, domain, api_keys["securitytrails_api_key"]))
            if api_keys.get("shodan_api_key"):
                futures.append(executor.submit(enumerate_subdomains_shodan, domain, api_keys["shodan_api_key"]))

        combined_subdomains = []
        for future in futures:
            combined_subdomains += future.result()

    return list(dict.fromkeys([sub for sub in combined_subdomains if not sub.startswith("www.")]))

def enumerate_subdomains_crtsh(domain):
    """
    Gets subdomains from crt.sh
    """
    url = f"https://crt.sh/?q={domain}"
    try:
        response = requests.get(url, timeout=5)
        subdomains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+' + re.escape(domain) + r'\b', str(response.text))
        return list(dict.fromkeys(subdomains))  # Remove duplicates
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from crt.sh: {e}")
        return []

def enumerate_subdomains_hackertarget(domain):
    """
    Gets subdomains from hackertarget.com
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            subdomains = [line.split(",")[0] for line in response.text.splitlines()]
            return list(dict.fromkeys(subdomains))  # Remove duplicates
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from hackertarget.com")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from hackertarget.com: {e}")
        return []

def enumerate_subdomains_threatcrowd(domain):
    """
    Gets subdomains from threatcrowd.org with disabled SSL verification due to certificate issues.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Suppress warnings

    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        response = requests.get(url, timeout=5, verify=False)  # SSL verification disabled
        if response.status_code == 200:
            json_response = response.json()
            if 'subdomains' in json_response:
                subdomains = json_response['subdomains']
                return list(dict.fromkeys(subdomains))  # Remove duplicates
            else:
                return []
        else:
            # Suppress output or redirect to stderr
            return []
    except requests.RequestException:
        return []

def enumerate_subdomains_certspotter(domain):
    """
    Fetches subdomains from CertSpotter's certificate transparency logs.
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            json_response = response.json()
            subdomains = []
            for entry in json_response:
                subdomains.extend(entry.get('dns_names', []))
            subdomains = [sub for sub in subdomains if not sub.startswith("www.")]
            return list(dict.fromkeys(subdomains))
        else:
            return []
    except requests.RequestException:
        return []
    
def enumerate_subdomains_anubis(domain):
    """
    Fetches subdomains from AnubisDB.
    """
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            subdomains = response.json()
            # Filter out duplicates and www subdomains
            subdomains = [sub for sub in subdomains if not sub.startswith("www.")]
            return list(dict.fromkeys(subdomains))
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from AnubisDB. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from AnubisDB: {e}")
        return []
    
def enumerate_subdomains_securitytrails(domain, api_key):
    """
    Fetches subdomains from SecurityTrails API.
    """
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        'APIKEY': api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            json_response = response.json()
            subdomains = json_response.get('subdomains', [])
            return [f"{sub}.{domain}" for sub in subdomains]  # Append domain to subdomains
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from SecurityTrails. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from SecurityTrails: {e}")
        return []

def enumerate_subdomains_shodan(domain, api_key):
    """
    Fetches subdomains from Shodan API.
    """
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            json_response = response.json()
            subdomains = json_response.get('subdomains', [])
            return [f"{sub}.{domain}" for sub in subdomains]  # Append domain to subdomains
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from Shodan. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from Shodan: {e}")
        return []

def probe_single_subdomain(subdomain, protocol, filter_http_codes=None):
    url = protocol + subdomain
    try:
        response = requests.get(url, timeout=3, allow_redirects=False)
        status_code = response.status_code
        if 200 <= status_code < 300:
            colored_status = f"{Fore.GREEN}[{status_code}]{Style.RESET_ALL}"
        elif 300 <= status_code < 400:
            # Recognition of redirects
            redirect_url = response.headers.get('Location', '')
            colored_status = f"{Fore.YELLOW}[{status_code} -> {redirect_url}]{Style.RESET_ALL}"
        elif 400 <= status_code < 500:
            colored_status = f"{Fore.RED}[{status_code}]{Style.RESET_ALL}"
        elif 500 <= status_code < 600:
            colored_status = f"{Fore.MAGENTA}[{status_code}]{Style.RESET_ALL}"
        else:
            colored_status = f"[{status_code}]"

        if filter_http_codes is None or status_code in filter_http_codes:
            return f"{colored_status} {subdomain} ({protocol})"
    except requests.exceptions.RequestException:
        if filter_http_codes is None or "UNR" in filter_http_codes:
            return f"[UNR] {subdomain} ({protocol})"

    return None

def probe_subdomains(subdomains, filter_http_codes=None):
    results = []
    max_workers = os.cpu_count() * 2
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_results = []
        for subdomain in subdomains:
            for protocol in ['http://', 'https://']:
                future = executor.submit(probe_single_subdomain, subdomain, protocol, filter_http_codes)
                future_results.append(future)
        
        for future in future_results:
            result = future.result()
            if result:
                results.append(result)
    
    return results

def write_subdomains_to_file(subdomains, filename, prefix=""):
    """
    Writes the subdomains into an output file. Prefix is optional to use (http/https).
    """
    with open(filename, 'w') as f:
        for subdomain in subdomains:
            f.write(f"{prefix}{subdomain}\n")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Subdomains were exported into following file: '{filename}'.")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Script")
    parser.add_argument('-d', '--domain', type=str, help='The domain for which subdomains are to be enumerated.')
    parser.add_argument('-p', '--probe', action='store_true', help='Check subdomains for HTTP/HTTPS status codes.')
    parser.add_argument("-hc", "--httpCode", type=str, help="HTTP codes for filtering, separated by a comma (e.g. 200,401,403).")
    parser.add_argument('-o', '--output', type=str, help='Output file name. Specifies the file name to which the subdomains are to be exported.')
    parser.add_argument('-ohttp', action='store_true', help='Adds string in front of every subdomain: http://.')
    parser.add_argument('-ohttps', action='store_true', help='Adds string in front of every subdomain: https://')
    parser.add_argument('-u', '--update', action='store_true', help='Switch parameter to update the tool.')
    parser.add_argument('-api', action='store_true', help='Include sources that require API keys (configure in config.json).')
    
    args = parser.parse_args()
    
    if args.update:
        check_for_updates()
        return

    if args.domain:
        subdomains = enumerate_subdomains(args.domain, use_api=args.api)

        if args.probe:
            if args.httpCode:
                http_code_filter = list(map(int, args.httpCode.split(',')))
            else:
                http_code_filter = None
            results = probe_subdomains(subdomains, http_code_filter)
            print("\n".join(results))
        else:
            print("\n".join(subdomains))

        if args.output:
            prefix = ""
            if args.ohttp:
                prefix = "http://"
            elif args.ohttps:
                prefix = "https://"

            write_subdomains_to_file(subdomains, args.output, prefix=prefix)

if __name__ == "__main__":
    main()
