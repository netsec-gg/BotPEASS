import requests
import datetime
import pathlib
import json
import os
import vulners  # Ensure the vulners library is installed
from os.path import join
from enum import Enum
from discord import Webhook, RequestsWebhookAdapter

# Define constants and paths
CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Initialize global variables for last processed CVE times
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)

# Enum for time type filtering
class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"

# Function to load the last processed times for new and modified CVEs
def load_lasttimes():
    global LAST_NEW_CVE, LAST_MODIFIED_CVE
    try:
        with open(CVES_JSON_PATH, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = datetime.datetime.strptime(cves_time["LAST_NEW_CVE"], TIME_FORMAT)
            LAST_MODIFIED_CVE = datetime.datetime.strptime(cves_time["LAST_MODIFIED_CVE"], TIME_FORMAT)
    except Exception as e:
        print(f"ERROR, using default last times. Error: {e}")

    print(f"Last new CVE: {LAST_NEW_CVE}")
    print(f"Last modified CVE: {LAST_MODIFIED_CVE}")

# Function to update the last processed times for new and modified CVEs
def update_lasttimes():
    with open(CVES_JSON_PATH, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)

# Function to retrieve CVEs based on a time filter (either published or last modified)
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

# Function to filter CVEs by their published or last modified time
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

# Function to search for public exploits using Vulners
def search_exploits(cve_id: str) -> list:
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    if vulners_api_key:
        vul_api = vulners.Vulners(api_key=vulners_api_key)
        exploits = vul_api.searchExploits(cve_id)
        return [exploit['title'] for exploit in exploits.get('data', [])]
    else:
        print("VULNERS_API_KEY is not set. Skipping exploit search.")
        return []

# Placeholder functions for generating messages (adapt as needed)
def generate_new_cve_message(cve_data: dict, exploits: list) -> str:
    # Adapt this function to include exploits in the message
    message = f"🚨 New CVE: {cve_data['id']} 🚨\n"
    message += f"- CVSS: {cve_data.get('cvss', 'N/A')}\n"
    message += f"- Published: {cve_data.get('Published', 'N/A')}\n"
    message += f"- Summary: {cve_data.get('summary', 'N/A')[:500]}\n"
    if exploits:
        message += "- Exploits:\n" + "\n".join(exploits)
    return message

def generate_modified_cve_message(cve_data: dict, exploits: list) -> str:
    # Adapt this function to include exploits in the message
    message = f"✏️ Modified CVE: {cve_data['id']}\n"
    message += f"- CVSS: {cve_data.get('cvss', 'N/A')}\n"
    message += f"- Last Modified: {cve_data.get('last-modified', 'N/A')}\n"
    if exploits:
        message += "- Exploits:\n" + "\n".join(exploits)
    return message

# Placeholder function for sending messages
def send_message(message: str):
    print(message)  # Replace with actual code to send messages to your desired platform

# Main function to process new and modified CVEs
def main():
    load_lasttimes()

    # Process new CVEs
    new_cves = get_cves(Time_Type.PUBLISHED)["results"]
    filtered_new_cves, new_last_new_cve = filter_cves(new_cves, LAST_NEW_CVE, Time_Type.PUBLISHED)
    global LAST_NEW_CVE
    LAST_NEW_CVE = new_last_new_cve
    for cve in filtered_new_cves:
        exploits = search_exploits(cve['id'])
        message = generate_new_cve_message(cve, exploits)
        send_message(message)

    # Process modified CVEs
    modified_cves = get_cves(Time_Type.LAST_MODIFIED)["results"]
    filtered_modified_cves, new_last_modified_cve = filter_cves(modified_cves, LAST_MODIFIED_CVE, Time_Type.LAST_MODIFIED)
    global LAST_MODIFIED_CVE
    LAST_MODIFIED_CVE = new_last_modified_cve
    for cve in filtered_modified_cves:
        exploits = search_exploits(cve['id'])
        message = generate_modified_cve_message(cve, exploits)
        send_message(message)

    update_lasttimes()

if __name__ == "__main__":
    main()
