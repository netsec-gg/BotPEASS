import requests
import datetime
import pathlib
import json
import os
from os.path import join
from enum import Enum

# Import the correct Vulners API class
import vulners

# Define constants and paths
CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

# Initialize global variables for last processed CVE times
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)

class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"

# Assuming load_lasttimes, update_lasttimes, get_cves, filter_cves functions remain the same

def search_exploits(cve_id: str) -> list:
    '''Search for public exploits related to a given CVE ID using the updated Vulners API'''
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    if vulners_api_key:
        vul_api = vulners.VulnersApi(api_key=vulners_api_key)
        search_query = f"cve:{cve_id}"
        exploit_results = vul_api.find_exploit_all(search_query)
        # Ensure exploit_results is correctly handled based on its actual structure
        exploits = [f"{item.get('title', 'No title')} - {item.get('href', 'No link')}" for item in exploit_results]
        return exploits
    else:
        print("VULNERS_API_KEY wasn't configured in the secrets!")
        return []

def send_message(cve_data, exploits=[]):
    # Correctly access the 'cvss' field considering cve_data might be a nested structure from Vulners response
    cvss_score = cve_data.get('cvss', {}).get('score', 'N/A') if cve_data.get('cvss') else 'N/A'
    details_link = cve_data.get('href', 'No details available')
    exploit_details = "\n".join(exploits) if exploits else "No public exploits found."
    message = (
        f"🚨 CVE ID: {cve_data.get('id', 'N/A')}\n"
        f"Summary: {cve_data.get('summary', 'N/A')}\n"
        f"CVSS: {cvss_score}\n"
        f"CWE: {','.join(cve_data.get('cwe', ['Unknown']))}\n"
        f"Published: {cve_data.get('published', 'N/A')}\n"
        f"Last Modified: {cve_data.get('modified', 'N/A')}\n"
        f"Assigner: {cve_data.get('reporter', 'N/A')}\n"
        f"Details: {details_link}\n"
        "References:\n" + "\n".join(cve_data.get('references', [])) +
        "\nExploits:\n" + exploit_details
    )
    data = {"content": message}
    response = requests.post(DISCORD_WEBHOOK_URL, json=data)
    if response.status_code != 204:
        print(f"Error sending message to Discord: {response.status_code}, {response.text}")

# main function and other necessary functions remain the same

if __name__ == "__main__":
    main()


