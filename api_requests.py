import os
import requests
import re
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

# Configuration de l'URL
BASE_URL = "https://vivalia.iot.paloaltonetworks.com"
API_VERSION = "v4.0"
CUSTOMER_ID = "vivalia"

# En-têtes pour les requêtes API
HEADERS = {
    "X-Key-Id": os.getenv("ACCESS_KEY_ID"),
    "X-Access-Key": os.getenv("SECRET_ACCESS_KEY"),
}

NVD_HEADERS = {"apiKey": os.getenv("NVD_KEY")}


# Fonction pour effectuer une requête HTTP GET
def make_get_request(url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Échec de la requête HTTP : {e}")
        pass


def get_vuln_info(vuln_name):
    url = f"{BASE_URL}/pub/{API_VERSION}/vulnerability/list?customerid={CUSTOMER_ID}&groupby=device&name={vuln_name}"
    data = make_get_request(url, HEADERS)
    return data


def parse_vuln_info(data):
    vulnerabilities_dict = {}
    for vuln in data.get("items", []):
        name = vuln["name"]
        ip = vuln["ip"]
        profile = vuln["profile"]
        site = vuln["siteName"]

        if name not in vulnerabilities_dict:
            vulnerabilities_dict[name] = []
        vulnerabilities_dict[name].append([ip, profile, site])

    # sort the dict by IP
    vulnerabilities_dict = dict(
        sorted(vulnerabilities_dict.items(), key=lambda item: item[1][0][0])
    )

    return vulnerabilities_dict


def get_description(cve_name):
    url = f"https://vulnerability.circl.lu/api/cve/{cve_name}"
    data = make_get_request(url, NVD_HEADERS)

    if data:
        descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value")
    return "English description not found"

"""
Ancienne version avec API du NIST   
    if data:
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            descriptions = vulnerabilities[0].get("cve", {}).get("descriptions", [])
            for description in descriptions:
                if description.get("lang") == "en":
                    value = description.get("value")
                    # Clean the description (all HTML tags)
                    clean = re.sub("<.*?>", "", value)
                    return clean
    return "Description non trouvée"
"""
"""
def get_recommendation(cve_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_name}"
    data = make_get_request(url, NVD_HEADERS)

    if data:
        recommendation = data.get("vulnerabilities", [])[0].get("cve", {}).get("cisaRequiredAction", "")
        if recommendation:
            return recommendation
    return "Recommandation non trouvée"
"""