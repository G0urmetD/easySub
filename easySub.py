import os
import re
import argparse
import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def print_banner():
    banner = f"""{Fore.MAGENTA}
    --------------------------------------
    |   easySub                          |
    |                                    |
    |    Author: G0urmetD                |
    |    Version: 1.0                    |
    --------------------------------------
    {Style.RESET_ALL}"""
    print(banner)

def enumerate_subdomains(domain):
    response = requests.get("https://crt.sh/?q=" + domain)
    mylist = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+' + re.escape(domain) + r'\b', str(response.text))
    mylist = [sub for sub in mylist if not sub.startswith("www.")]
    return list(dict.fromkeys(mylist))

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

def get_output_filename(filename=None):
    if filename:
        return filename
    
    base_filename = "easySub-Export"
    counter = 1
    while True:
        output_file = f"{base_filename}-{counter:03}.txt"
        if not os.path.exists(output_file):
            return output_file
        counter += 1

def write_subdomains_to_file(subdomains, filename, filter_method):
    with open(filename, 'w') as f:
        for subdomain in subdomains:
            if filter_method == "http":
                f.write(f"http://{subdomain}\n")
            elif filter_method == "https":
                f.write(f"https://{subdomain}\n")
            else:
                f.write(f"{subdomain}\n")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Script")
    parser.add_argument('-d', '--domain', type=str, required=True, help='The domain for which subdomains are to be enumerated.')
    parser.add_argument('-p', '--probe', action='store_true', help='Check subdomains for HTTP/HTTPS status codes.')
    parser.add_argument("-hc", "--httpCode", type=str, help="HTTP codes for filtering, separated by a comma (e.g. 200,401,403).")
    parser.add_argument('-o', '--output', type=str, help='Output file name. Specifies the file name to which the subdomains are to be exported.')
    parser.add_argument('-of', '--filteroutput', type=str, choices=['http', 'https'], help='Filter method for the output. Add either ‘http://’ or ‘https://’ in front of the subdomains.')
    parser.add_argument('-u', '--update', action='store_true', help='Switch parameter to update the tool.')
    
    args = parser.parse_args()
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

    if args.output is not None:
        output_file = get_output_filename(args.output if isinstance(args.output, str) else None)
        write_subdomains_to_file(subdomains, output_file, args.filteroutput)
        print("")
        print(f"[INF] Subdomains were exported to the file: '{output_file}'.")


if __name__ == "__main__":
    main()
