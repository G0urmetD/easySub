import sys
import requests
from colorama import Fore, Style

CURRENT_VERSION = "easySub-v1.2"

def check_for_updates():
    """
    Checks if a newer version is reachable from github.
    """
    response = requests.get("https://api.github.com/repos/G0urmetD/easySub/releases/latest")
    
    if response.status_code == 200:
        latest_version = response.json()['tag_name']
        if latest_version != CURRENT_VERSION:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Newer version found: {latest_version}. Current version: {CURRENT_VERSION}.")
            update_tool(latest_version)
        else:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} newest version is already installed.")
    else:
        print("{Fore.RED}[-]{Style.RESET_ALL} Error, could not check for a newer version.")

def update_tool(latest_version):
    """
    Download the newest version and replaces the current files.
    """
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Updating the tool ...")
    download_url = f"https://github.com/DeinUsername/easySub/releases/download/{latest_version}/easySub.py"
    
    response = requests.get(download_url)
    if response.status_code == 200:
        with open("easySub.py", "wb") as file:
            file.write(response.content)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} The tool was successfully updated.")
        sys.exit()
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Something went wrong during the download process.")
