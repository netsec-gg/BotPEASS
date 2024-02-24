import requests
import datetime
import pathlib
import json
import os
import vulners
from os.path import join
from enum import Enum

# Define constants and paths
CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"

# Initialize global variables for last processed CVE times
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)

# Enum for time type filtering
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
        exploits = vul_api.searchExploits(query=f"\"{cve_id}\"")
        return [exploit['title'] for exploit in exploits.get('data', []) if 'title' in exploit]
    else:
        print("VULNERS_API_KEY is not set. Skipping exploit search.")
        return []

def send_message(message: str):
    data = {"content": message}
    response = requests.post(DISCORD_WEBHOOK_URL, json=data)
    if response.status_code != 204:
        print(f"Error sending message to Discord: {response.status_code}, {response.text}")

def main():
    global LAST_NEW_CVE, LAST_MODIFIED_CVE
    
    load_lasttimes()

    # Process new CVEs
    new_cves = get_cves(Time_Type.PUBLISHED)["results"]
    filtered_new_cves, new_last_new_cve = filter_cves(new_cves, LAST_NEW_CVE, Time_Type.PUBLISHED)
    LAST_NEW_CVE = new_last_new_cve
    for cve in filtered_new_cves:
        exploits = search_exploits(cve['id'])
        message = f"🚨 New CVE: {cve['id']}\n- CVSS: {cve.get('cvss', 'N/A')}\n- Published: {cve.get('Published', 'N/A')}\n- Summary: {cve.get('summary', 'N/A')[:500]}\n"
        if exploits:
            message += "- Exploits:\n" + "\n".join(exploits)
        send_message(message)

    # Process modified CVEs
    modified_cves = get_cves(Time_Type.LAST_MODIFIED)["results"]
    filtered_modified_cves, new_last_modified_cve = filter_cves(modified_cves, LAST_MODIFIED_CVE, Time_Type.LAST_MODIFIED)
    LAST_MODIFIED_CVE = new_last_modified_cve
    for cve in filtered_modified_cves:
        exploits = search_exploits(cve['id'])
        message = f"✏️ Modified CVE: {cve['id']}\n- CVSS: {cve.get('cvss', 'N/A')}\n- Last Modified: {cve.get('last-modified', 'N/A')}\n"
        if exploits:
            message += "- Exploits:\n" + "\n".join(exploits)
        send_message(message)

    update_lasttimes()

if __name__ == "__main__":
    main()

