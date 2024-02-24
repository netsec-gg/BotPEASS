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
    '''Search for public exploits related to a given CVE ID using the updated Vulners API'''
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    if vulners_api_key:
        vul_api = vulners.VulnersApi(api_key=vulners_api_key)
        search_query = f"cve:{cve_id}"
        exploit_results = vul_api.find_exploit_all(search_query)
        exploits = [f"{item.get('title', 'No title')} - {item.get('href', 'No link')}" for item in exploit_results]
        return exploits
    else:
        print("VULNERS_API_KEY wasn't configured in the secrets!")
        return []

def send_message(cve_data, exploits=[]):
    details_link = cve_data.get('href', 'No details available')
    exploit_details = "\n".join(exploits) if exploits else "No public exploits found."
    message = (
        f"🚨 CVE ID: {cve_data['id']}\n"
        f"Summary: {cve_data.get('summary', 'N/A')}\n"
        f"CVSS: {cve_data.get('cvss', {}).get('score', 'N/A')}\n"
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

def main():
    global LAST_NEW_CVE, LAST_MODIFIED_CVE
    
    load_lasttimes()

    new_cves = get_cves(Time_Type.PUBLISHED)["results"]
    filtered_new_cves, new_last_new_cve = filter_cves(new_cves, LAST_NEW_CVE, Time_Type.PUBLISHED)
    LAST_NEW_CVE = new_last_new_cve
    for cve in filtered_new_cves:
        exploits = search_exploits(cve['id'])
        send_message(cve, exploits)

    modified_cves = get_cves(Time_Type.LAST_MODIFIED)["results"]
    filtered_modified_cves, new_last_modified_cve = filter_cves(modified_cves, LAST_MODIFIED_CVE, Time_Type.LAST_MODIFIED)
    LAST_MODIFIED_CVE = new_last_modified_cve
    for cve in filtered_modified_cves:
        exploits = search_exploits(cve['id'])
        send_message(cve, exploits)

    update_lasttimes()

if __name__ == "__main__":
    main()

