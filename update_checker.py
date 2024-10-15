import os
import io
import sys
import json
import shutil
import zipfile
import requests
from colorama import Fore, Style

def load_config():
    with open("config.json") as config_file:
        return json.load(config_file)

config = load_config()
CURRENT_VERSION = config["version"]

# def check_for_updates():
#     """
#     Checks if a newer version is available from GitHub.
#     """
#     try:
#         response = requests.get("https://api.github.com/repos/G0urmetD/easySub/releases/latest")
#         response.raise_for_status()

#         latest_version = response.json()['tag_name']
#         if latest_version != CURRENT_VERSION:
#             print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Newer version found: {latest_version}. Current version: {CURRENT_VERSION}.")
#             update_tool(latest_version)
#         else:
#             print(f"{Fore.GREEN}[+]{Style.RESET_ALL} The newest version is already installed.")
#     except requests.RequestException as e:
#         print(f"{Fore.RED}[-]{Style.RESET_ALL} Error: could not check for a newer version. {str(e)}")

def check_for_updates():
    """
    Checks if a newer version is available from GitHub.
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
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error, could not check for a newer version.")

def update_tool(latest_version):
    """
    Downloads the newest version, unzips all the files, and replaces them in the current directory.
    """
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Updating the tool ...")
    
    download_url = f"https://github.com/G0urmetD/easySub/archive/refs/tags/{latest_version}.zip"
    
    try:
        response = requests.get(download_url)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            zip_file.extractall("easySub_temp")
            
        extracted_folder = os.path.join("easySub_temp", os.listdir("easySub_temp")[0])
        
        if not os.path.isdir(extracted_folder):
            raise FileNotFoundError(f"{extracted_folder} does not exist.")
        
        for root, dirs, files in os.walk(extracted_folder):
            for file in files:
                file_path = os.path.join(root, file)
                destination_path = os.path.join(os.getcwd(), file)
                
                shutil.copy2(file_path, destination_path)
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Updated {file}")
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} The tool was successfully updated.")
        sys.exit()
    except requests.RequestException as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Something went wrong during the download process: {str(e)}")
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Error extracting the zip file: {str(e)}")
    finally:
        if os.path.exists("easySub_temp"):
            shutil.rmtree("easySub_temp")
