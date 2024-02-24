import requests
import datetime
import json
import os
from os.path import join
from enum import Enum

# Import the Vulners library with the correct API class
import vulners

# Define constants and paths
CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(os.path.dirname(__file__), "output/botpeas.json")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

# Initialize global variables for last processed CVE times
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)

class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"

def load_lasttimes():
    global LAST_NEW_CVE, LAST_MODIFIED_CVE
    try:
        with open(CVES_JSON_PATH, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = datetime.datetime.strptime(cves_time["LAST_NEW_CVE"], TIME_FORMAT)
            LAST_MODIFIED_CVE = datetime.datetime.strptime(cves_time["LAST_MODIFIED_CVE"], TIME_FORMAT)
    except FileNotFoundError:
        print("CVES_JSON_PATH file not found, using default last times.")

def update_lasttimes():
    with open(CVES_JSON_PATH, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)

def get_cves(tt_filter: Time_Type) -> dict:
    now = datetime.datetime.now() - datetime.timedelta(days=1)
    now_str = now.strftime("%Y-%m-%d")
    params = {
        "time_modifier": "from",
        "time_start": now_str,
        "time_type": tt_filter.value,
        "limit": "100",
    }
    response = requests.get(CIRCL_LU_URL, params=params)
    return response.json()

def filter_cves(cves: list, last_time: datetime.datetime, tt_filter: Time_Type) -> (list, datetime.datetime):
    filtered_cves = []
    new_last_time = last_time
    for cve in cves:
        cve_time = datetime.datetime.strptime(cve[tt_filter.value], TIME_FORMAT)
        if cve_time > last_time:
            filtered_cves.append(cve)
            if cve_time > new_last_time:
                new_last_time = cve_time
    return filtered_cves, new_last_time

def search_exploits(cve_id: str) -> list:
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    if vulners_api_key:
        vul_api = vulners.Vulners(api_key=vulners_api_key)
        search_query = f"cve:{cve_id}"
        exploit_results = vul_api.search(query=search_query, limit=10)
        exploits = [f"{item.get('title', 'No title')} - {item.get('href', '')}" for item in exploit_results.get('documents', {}).values()]
        return exploits
    else:
        print("VULNERS_API_KEY wasn't configured in the secrets!")
        return []

def send_message(cve_id, cve_data, exploits=[]):
    details_link = cve_data.get('href', 'No details available')
    exploit_details = "\n".join(exploits) if exploits else "No public exploits found."
    message = (
        f"🚨 CVE ID: {cve_id}\n"
        f"Summary: {cve_data.get('description', 'N/A')}\n"
        f"CVSS Score: {cve_data.get('cvss', {}).get('score', 'N/A')}\n"
        f"Published: {cve_data.get('published', 'N/A')}\n"
        f"Last Modified: {cve_data.get('modified', 'N/A')}\n"
        f"Details: {details_link}\n"
        "References:\n" + "\n".join(cve_data.get('references', ['No references available'])) +
        "\nExploits:\n" + exploit_details
    )
    data = {"content": message}
    response = requests.post(DISCORD_WEBHOOK_URL, json=data)
    if response.status_code != 204:
        print(f"Error sending message to Discord: {response.status_code}, {response.text}")

def main():
    global LAST_NEW_CVE, LAST_MODIFIED_CVE
    
    load_lasttimes()

    # Example for demonstration, should be replaced with actual data fetching logic
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    if vulners_api_key:
        vul_api = vulners.Vulners(api_key=vulners_api_key)
        cve_id = "CVE-2021-33111"  # Example CVE ID
        cve_data = vul_api.document(cve_id)
        if cve_data.get('result') == 'OK':
            cve_info = cve_data.get('data', {}).get('documents', {}).get(cve_id, {})
            exploits = search_exploits(cve_id)
            send_message(cve_id, cve_info, exploits)
        else:
            print(f"Failed to fetch data for {cve_id}")

    update_lasttimes()

if __name__ == "__main__":
    main()
