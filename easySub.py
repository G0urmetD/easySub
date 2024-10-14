import re
import argparse
import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
from update_checker import check_for_updates

init(autoreset=True)
CURRENT_VERSION = "1.1.1"

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

def enumerate_subdomains(domain):
    """
    Combines subdomains from crt.sh and hackertarget.com.
    """
    subdomains_crt = enumerate_subdomains_crtsh(domain)
    subdomains_hackertarget = enumerate_subdomains_hackertarget(domain)
    subdomains_threatcrowd = enumerate_subdomains_threatcrowd(domain)
    subdomains_certspotter = enumerate_subdomains_certspotter(domain)
    subdomains_anubis = enumerate_subdomains_anubis(domain)

    # Combine both lists and remove duplicates
    combined_subdomains = list(dict.fromkeys(subdomains_crt + subdomains_hackertarget + subdomains_threatcrowd + subdomains_certspotter + subdomains_anubis))
    
    # Filter out 'www.' prefixed domains if needed
    combined_subdomains = [sub for sub in combined_subdomains if not sub.startswith("www.")]

    return combined_subdomains

def enumerate_subdomains_crtsh(domain):
    """
    Gets subdomains from crt.sh
    """
    url = f"https://crt.sh/?q={domain}"
    try:
        response = requests.get(url, timeout=5)
        subdomains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+' + re.escape(domain) + r'\b', str(response.text))
        #mylist = [sub for sub in mylist if not sub.startswith("www.")]
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
            #mylist = [sub for sub in mylist if not sub.startswith("www.")]
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
                print(f"{Fore.YELLOW}[!] No subdomains found on ThreatCrowd for {domain}.")
                return []
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from ThreatCrowd. Status code: {response.status_code}")
            print(f"Response content: {response.content}")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from ThreatCrowd: {e}")
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
            # Remove duplicates and filter out www
            subdomains = [sub for sub in subdomains if not sub.startswith("www.")]
            return list(dict.fromkeys(subdomains))
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Failed to retrieve data from CertSpotter. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error while fetching from CertSpotter: {e}")
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
    with ThreadPoolExecutor(max_workers=10) as executor:
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
    
    args = parser.parse_args()
    
    if args.update:
        check_for_updates()
        return

    if args.domain:
        subdomains = enumerate_subdomains(args.domain)

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
