#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import time
import csv
import io
import sys
import os
import urllib3
import json
import smtplib
import copy
import re 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from dotenv import load_dotenv

# Load the environment variables from the .env file
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# INSIGHTVM CONFIG
# =========================================================
# Access InsightVM credentials and URL from environment variables
IVM_URL = os.getenv("IVM_URL")
IVM_PASS = os.getenv("IVM_PASS")
IVM_USER = os.getenv("IVM_USER")
# IVM_URL = "http://127.0.0.1:8765"
# IVM_USER = "user"
# IVM_PASS = "password"
# REPORT_IDS = ["52", "59"]
REPORT_IDS = [
    #"66" #Service Assurance
    #"53", #Big Data
    "52", #BI
    #"56", #CRM
    "59" #DE 
    #"60", #EIOM
    #"64" #IPCC
    #"70" #OSS 
    #"63" #ERP 
    #"58", #CVM 
    #"55", #Core Roaming
    #"71", #NMS 
    #"231" #G3 Jumpboxes
    #"65" #IT Infra
    #"67",
    #"89",
    #"32"
]

if os.getenv("PATCH_REPORT_IDS"):
    REPORT_IDS = [r.strip() for r in os.getenv("PATCH_REPORT_IDS").split(",") if r.strip()]

DRY_RUN = os.getenv("DRY_RUN") == "1"
FAILURES = []   # collected so the process exits non-zero

# =========================================================
# GITLAB CONFIG
# =========================================================
GITLAB_URL = os.getenv("GITLAB_URL")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
GITLAB_PROJECT_ID = os.getenv("GITLAB_PROJECT_ID")
GITLAB_BRANCH = os.getenv("GITLAB_BRANCH", "main")  # Default to "main" if not set

# GitLab repository paths
#CONTROL_PATH = "inventory/remediation_control.json"

# =========================================================
# CATEGORY GROUPS
# =========================================================
WINDOWS_CATEGORIES = {
    "chrome",
    "firefox",
    "edge",
    "wireshark",
    "notepadplusplus",
    "jabber",
    "winrar",
    "7zip",
    "winscp",
    "java_jre",
    "vscode",
    "vmwaretools",
    "silverlight",
    "msxml4",
    "dotnet",
    "defender",
    "sql",
    "sql2012",          # <-- ADD
    "sql2014",          # <-- ADD
    "sql2016",          # <-- ADD
    "sql2017",          # <-- ADD
    "sql2019",          # <-- ADD
    "sql2022",          # <-- ADD
    #"windowsos",
    "windowsos2016",   # added
    "windowsos2019",   # added
    "windowsos2022",   # added
    "CVE-2013-3900",
    "CVE-2022-0001",
    "W_TLS_1.0_1.1",
    "W_TLS_Sweet32",
    "W_TLS_HMAC",
    "W_TLS_StaticKeys",
    "insecureftp",
    "netbios_nbstat",
    "v_info_disclosure"
}

LINUX_CATEGORIES = {
    "RhelOS",
    "R_SSH_HMAC",
    "R_SSH_CBC",
    "R_SSH_KEX",
    "ICMP"
}

# =========================================================
# FRIENDLY CATEGORY NAMES (EMAIL DISPLAY ONLY)
# =========================================================
CATEGORY_NAMES = {

    #"windowsos": "Windows OS Patching",
    "windowsos2016": "Windows Server 2016 OS Patching",

    "windowsos2019": "Windows Server 2019 OS Patching",

    "windowsos2022": "Windows Server 2022 OS Patching",

    "chrome": "Google Chrome",

    "firefox": "Mozilla Firefox",

    "edge": "Microsoft Edge",

    "wireshark": "Wireshark",

    "notepadplusplus": "Notepad++",

    "jabber": "Cisco Jabber",

    "winrar": "WinRAR",

    "7zip": "7-Zip",

    "winscp": "WinSCP",

    "java_jre": "Java Runtime Environment",

    "vscode": "Microsoft VS Code",

    "vmwaretools": "Vmware Tools",

    "silverlight": "Microsoft Silverlight",

    "msxml4": "Microsoft MSXML4",

    "dotnet": "Microsoft .NET Framework",

    "defender": "Microsoft Defender CVE",

    "sql": "Microsoft SQL Server",

    "sql2012": "Microsoft SQL Server 2012",     # <-- ADD
    "sql2014": "Microsoft SQL Server 2014",     # <-- ADD
    "sql2016": "Microsoft SQL Server 2016",     # <-- ADD
    "sql2017": "Microsoft SQL Server 2017",     # <-- ADD
    "sql2019": "Microsoft SQL Server 2019",     # <-- ADD
    "sql2022": "Microsoft SQL Server 2022",     # <-- ADD

    "CVE-2013-3900": "CVE-2013-3900",

    "CVE-2022-0001": "Intel Branch History Injection",

    "W_TLS_1.0_1.1": "TLS 1.0 / TLS 1.1",

    "W_TLS_Sweet32": "TLS SWEET32",

    "W_TLS_HMAC": "Weak TLS HMAC",

    "W_TLS_StaticKeys": "TLS Static Key Ciphers",

    "insecureftp": "Unencrypted FTP",

    "netbios_nbstat": "netBIOS NBSTAT",

    "RhelOS": "Red Hat Enterprise Linux",

    "R_SSH_HMAC": "SSH Weak HMAC",

    "R_SSH_CBC": "SSH CBC Ciphers",

    "R_SSH_KEX": "SSH Weak Key Exchange",

    "ICMP": "ICMP Redirect",

    "v_info_disclosure": "v_info_disclosure"

   

}

# =========================================================
# EMAIL CONFIG
# =========================================================
EMAIL_MODE = os.getenv("EMAIL_MODE", "file").lower()

SMTP_SERVER = os.getenv("SMTP_SERVER", "172.28.120.58")
SMTP_PORT = os.getenv("SMTP_PORT", 25)

EMAIL_FROM = os.getenv("EMAIL_FROM", "gogomax017@gmail.com")
# EMAIL_TO = os.getenv("EMAIL_TO", "onyangogogo2002@gmail.com")
EMAIL_TO = [
    email.strip()
    for email in os.getenv(
        "EMAIL_TO",
        "onyangogogo2002@gmail.com"
    ).split(",")
    if email.strip()
]

EMAIL_TEST_DIR = os.getenv(
    "EMAIL_TEST_DIR",
    "email_test"
)

# EMAIL_TO = [
#     #"endpointsecurity@safaricomO365.onmicrosoft.com",
#     # "sgogo@safaricom.co.ke"
#     #"gmunga@safaricom.co.ke"
# ]

EMAIL_SUBJECT = "Automated Remediation Report - {date}"


# =========================================================
# REPORT TEAM EMAILS
# =========================================================

REPORT_EMAILS = {

    "66": {
        "team": "Service Assurance Team",
        "emails": [
            #"infrastructure@domain.local"
            
        ]
    },

    "53": {
        "team": "Big Data Team",
        "emails": [
            #"database@domain.local"
            "max@gmail.com"
        ]
    },

    "52": {
        "team": "BI Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "56": {
        "team": "CRM Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "59": {
        "team": "DE Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "60": {
        "team": "EIOM Team",
        "emails": [
            #"infrastructure@domain.local"
            "max@gmail.com"
        ]
    },

    "64": {
        "team": "IPCC Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "70": {
        "team": "OSS Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "63": {
        "team": "ERP Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "58": {
        "team": "CVM Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "55": {
        "team": "Core Roaming Team",
        "emails": [
           # "applications@domain.local"
        ]
    },

    "71": {
        "team": "NMS Team",
        "emails": [
            #"infrastructure@domain.local"
            "max@gmail.com"
        ]
    },

    "231": {
        "team": "G3 Jumpboxes Team",
        "emails": [
            #"infrastructure@domain.local"
            "max@gmail.com"
        ]
    },

    "65": {
        "team": "IT Infra Team",
        "emails": [
            #"infrastructure@domain.local"
            "mx2@gmail.com"
        ]
    }

    

    

    

}


# =========================================================
# DOWNLOAD REPORT
# =========================================================
def download_report(base_url, username, password, report_id):

    generate_url = f"{base_url}/api/3/reports/{report_id}/generate"

    response = requests.post(
        generate_url,
        auth=HTTPBasicAuth(username, password),
        verify=False,
        headers={"Content-Type": "application/json"},
        json={}
    )

    if response.status_code != 200:
        print("FAILED generating report")
        print(response.text)
        return None

    instance_id = response.json().get("id")

    print(f"[+] Report started: {instance_id}")

    status_url = (
        f"{base_url}/api/3/reports/"
        f"{report_id}/history/{instance_id}"
    )

    max_attempts = 60
    attempt = 0

    while True:

        attempt += 1

        if attempt > max_attempts:
            print("FAILED: Report timeout")
            return None

        status_response = requests.get(
            status_url,
            auth=HTTPBasicAuth(username, password),
            verify=False
        )

        status = status_response.json().get("status")

        print(f"[STATUS] {status}")

        if status == "complete":
            break

        if status == "failed":
            print("FAILED report generation")
            return None

        time.sleep(5)

    download_url = (
        f"{base_url}/api/3/reports/"
        f"{report_id}/history/{instance_id}/output"
    )

    report = requests.get(
        download_url,
        auth=HTTPBasicAuth(username, password),
        verify=False
    )

    if report.status_code != 200:
        print("FAILED downloading report")
        return None

    return report.content


# =========================================================
# EXTRACT ASSETS
# =========================================================
def extract_assets(csv_content):

    csv_file = io.StringIO(csv_content.decode("utf-8"))
    reader = csv.DictReader(csv_file)

    assets = {}

    for row in reader:

        ip = row.get("Asset IP Address")

        hostname = (
            row.get("Asset Names") or "unknown"
        ).split(",")[0].strip()
        
        asset_os_type = (
            row.get("Asset OS Name") or ""
        ).strip()

        asset_os_version = (
            row.get("Asset OS Version") or ""
        ).strip()

        vuln_title = (
            row.get("Vulnerability Title") or ""
        ).strip()

        severity = (
            row.get("Severity") or "Unknown"
        ).strip()

        solution = (
            row.get("Solution")
            or row.get("Vulnerability Solution")
            or ""
        ).strip()

        vuln_proof = (                              # <-- ADD THIS BLOCK
            row.get("Vulnerability Proof")
            or row.get("Proof")
            or ""
        ).strip()

        if not ip or not vuln_title:
            continue

        # =================================================
        # CATEGORY MAPPING
        # =================================================
        if (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("Google Chrome")):
            category = "chrome"

        elif (asset_os_type.startswith("Microsoft Windows Server") 
            and vuln_title.startswith("MFSA")):
            category = "firefox"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("Microsoft Edge")):
            category = "edge"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("Wireshark")):
            category = "wireshark"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("NotepadPlusPlus")):
            category = "notepadplusplus"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("Cisco Jabber")):
            category = "jabber"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("Rarlab WinRAR")):
            category = "winrar"

        #elif (asset_os_type.startswith("Microsoft Windows Server")
        #    and vuln_title.startswith("7-Zip") or vuln_title.startswith("7-zip")):
        #    category = "7zip"
        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("7-Zip")
                or vuln_title.startswith("7-zip")
            )       
        ):
            category = "7zip"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("WinSCP")):
            category = "winscp"

        #elif (
        #    vuln_title.startswith("Java CPU")
        #    and asset_os_type.startswith("Microsoft Windows Server")
        #):
        #    category = "java_jre"

        elif (asset_os_type.startswith("Microsoft Windows Server")
              and (
                  vuln_title.startswith("Microsoft VS Code: CVE")
                
              )
        ):
            category = "vscode"

        elif (asset_os_type.startswith("Microsoft Windows Server")
              and (
                  vuln_title.startswith("Java CPU")
                  or vuln_title.startswith("Oracle Security Alert: Java vulnerability")
              )
        ):
            category = "java_jre"

        #elif (
        #    vuln_title.startswith("Microsoft .NET Framework")
        #    or ".NET Framework" in vuln_title
        #    ):
        #    category = "dotnet"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and 
                vuln_title.startswith("VMware VMware Tools: CVE")
            
        ):
            category = "vmwaretools"    

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Microsoft .NET Framework")
                or ".NET Framework" in vuln_title
            )
        ):
            category = "dotnet"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Microsoft Windows Defender: CVE")
            )
        ):
            category = "defender"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Obsolete Version of Microsoft Silverlight")
                or "Microsoft Silverlight" in vuln_title
            )
        ):
            category = "silverlight"


        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Obsolete version of Microsoft MSXML 4")
                or "Microsoft MSXML" in vuln_title
            )
        ):
            category = "msxml4"

        #elif (asset_os_type.startswith("Microsoft Windows Server")
        #    and "SQL" in vuln_title):
        #    category = "sql"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Microsoft SQL Server:")
                or "Microsoft SQL Server" in vuln_title
            )
        ):
            category = "sql"

        #elif (
        #    vuln_title.startswith("Microsoft Windows: CVE")
        #    and "KB" in solution
        #   and vuln_title != "Microsoft Windows: CVE-2022-0001: Intel: CVE-2022-0001 Branch History Injection"
        #    #doesn't contain sql, SQL,.NET,Visual Studio
        #    ):
        #    category = "windowsos"

        #elif (
        #    asset_os_type.startswith("Microsoft Windows Server")
        #    and vuln_title.startswith("Microsoft Windows: CVE")
        #    and "KB" in solution
        #    and "SQL" not in vuln_title
        #    and ".NET" not in vuln_title
        #    and "Visual Studio" not in vuln_title
        #    and vuln_title != "Microsoft Windows: CVE-2022-0001: Intel: CVE-2022-0001 Branch History Injection"
        #):
        #    category = "windowsos"


        elif (
            asset_os_type.startswith("Microsoft Windows Server 2016")
            and vuln_title.startswith("Microsoft Windows: CVE")
            and "KB" in solution
            and "SQL" not in vuln_title
            and ".NET" not in vuln_title
            and "Visual Studio" not in vuln_title
            and vuln_title != "Microsoft Windows: CVE-2022-0001: Intel: CVE-2022-0001 Branch History Injection"
            ):
            category = "windowsos2016"

        elif (
            asset_os_type.startswith("Microsoft Windows Server 2019")
            and (vuln_title.startswith("Microsoft Windows: CVE"))
            and "KB" in solution
            and "SQL" not in vuln_title
            and ".NET" not in vuln_title
            and "Visual Studio" not in vuln_title
            and vuln_title != "Microsoft Windows: CVE-2022-0001: Intel: CVE-2022-0001 Branch History Injection"
            ):
            category = "windowsos2019"

        elif (
            asset_os_type.startswith("Microsoft Windows Server 2022")
            and vuln_title.startswith("Microsoft Windows: CVE")
            and "KB" in solution
            #and "SQL" not in vuln_title
            #and ".NET" not in vuln_title
            #and "Visual Studio" not in vuln_title
            #and vuln_title != "Microsoft Windows: CVE-2022-0001: Intel: CVE-2022-0001 Branch History Injection"
            ):
            category = "windowsos2022"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and vuln_title.startswith("CVE-2013-3900: MS13-098")
            ):
            category = "CVE-2013-3900"

        elif (asset_os_type.startswith("Microsoft Windows Server")
            and (
                vuln_title.startswith("Microsoft Windows: CVE-2022-0001")
                or vuln_title.startswith("Microsoft Windows: Intel Branch History Injection: CVE-2022-0001")
            )
            ):
            category = "CVE-2022-0001"


        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("TLS Server Supports TLS version 1.0")
            or vuln_title.startswith("TLS Server Supports TLS version 1.1")
            or vuln_title.startswith("TLS/SSL Server is enabling the BEAST attack")
            )
            ):
            category = "W_TLS_1.0_1.1"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("TLS/SSL Birthday attacks on 64-bit block ciphers (SWEET32)")
            or vuln_title.startswith("TLS/SSL Server Supports 3DES Cipher Suite")
            )
            ):
            category = "W_TLS_Sweet32"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("TLS/SSL Weak Message Authentication Code Cipher Suites")
            )
            ):
            category = "W_TLS_HMAC"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("TLS/SSL Server Supports The Use of Static Key Ciphers")
            )
            ):
            category = "W_TLS_StaticKeys"

        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("FTP credentials transmitted unencrypted")
            )
            ):
            category = "insecureftp"
        
        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("NetBIOS NBSTAT Traffic Amplification")
            )
            ):
            category = "netbios_nbstat"
        
        elif (
            asset_os_type.startswith("Microsoft Windows Server")
            and (
            vuln_title.startswith("Microsoft CVE-2019-0537: Microsoft Visual Studio Information Disclosure Vulnerability")
            or vuln_title.startswith("Microsoft CVE-2018-1037: Microsoft Visual Studio Information Disclosure Vulnerability")
            )
            ):
            category = "v_info_disclosure"

#LINUX PATCHING

        elif (
            asset_os_type.startswith("Red Hat Enterprise Linux")
            and asset_os_version.startswith(("8", "9"))
            and (
            vuln_title.startswith("Red Hat: CVE-")
            )
            ):
            category = "RhelOS"

        elif (
            asset_os_type.startswith("Red Hat Enterprise Linux")
            and asset_os_version.startswith(("8", "9"))
            and (
            vuln_title.startswith("SSH Weak Message Authentication Code Algorithms")
            )
            ):
            category = "R_SSH_HMAC"

        elif (
            asset_os_type.startswith("Red Hat Enterprise Linux")
            and asset_os_version.startswith(("8", "9"))
            and (
            vuln_title.startswith("SSH CBC vulnerability")
            )
            ):
            category = "R_SSH_CBC"

        elif (
            asset_os_type.startswith("Red Hat Enterprise Linux")
            and asset_os_version.startswith(("8", "9"))
            and (
            vuln_title.startswith("SSH Server Supports Weak Key Exchange Algorithms")
            )
            ):
            category = "R_SSH_KEX"

        elif (
            asset_os_type.startswith("Red Hat Enterprise Linux")
            and asset_os_version.startswith(("8", "9"))
            and (
            vuln_title.startswith("ICMP redirection enabled")
            )
            ):
            category = "ICMP"
        

        else:
            category = "other"


        # =================================================
        # SQL SERVER VERSION SUB-CATEGORY
        # (adds an ADDITIONAL category alongside "sql", doesn't replace it)
        # =================================================
        sql_version_category = None

        if category == "sql":

            version_match = re.search(
                r"Microsoft SQL Server (\d{4})",
                vuln_proof
            )

            if version_match:
                year = version_match.group(1)
                sql_version_category = f"sql{year}"




        if ip not in assets:

            assets[ip] = {
                "hostname": hostname,
                "ip": ip,
                "os": asset_os_type,
                "os_version": asset_os_version,
                "categories": {}
            }

        if category not in assets[ip]["categories"]:
            assets[ip]["categories"][category] = []

        assets[ip]["categories"][category].append({
            "title": vuln_title,
            "severity": severity,
            "solution": solution
        })


        # =================================================
        # ADD TO VERSION SUB-CATEGORY TOO, IF DETECTED
        # =================================================
        if sql_version_category:

            if sql_version_category not in assets[ip]["categories"]:
                assets[ip]["categories"][sql_version_category] = []

            assets[ip]["categories"][sql_version_category].append({
                "title": vuln_title,
                "severity": severity,
                "solution": solution
            })


    return assets


# =========================================================
# BUILD CATEGORY JOBS
# =========================================================
def build_category_jobs(assets, category):

    jobs = []

    severity_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }

    for ip, data in assets.items():

        if category not in data["categories"]:
            continue

        vulns = data["categories"][category]

        highest = max(
            vulns,
            key=lambda x: severity_rank.get(
                x.get("severity") or "Unknown",
                0
            )
        )

        jobs.append({
            "hostname": data["hostname"],
            "ip": data["ip"],
            "os": data["os"],
            "os_version": data["os_version"],
            "category": category,
            "vuln_count": len(vulns),
            "severity": highest.get("severity"),
            "title": highest.get("title")
        })

    return jobs


# =========================================================
# CREATE CATEGORY INVENTORY
# =========================================================
def create_inventory(category_jobs, filename, parent_group, valid_categories, use_ip=False):

    os.makedirs(os.path.dirname(filename), exist_ok=True)

    lines = []
    # Keep only the categories we want

    filtered = {
        category: jobs
        for category, jobs in category_jobs.items()
        if category in valid_categories
    }
#OR
    #filtered_jobs = {}

    #for category, jobs in category_jobs.items():

    #    if category in valid_categories:
    #        filtered_jobs[category] = jobs

    #create category groups
    for category, jobs in filtered.items():

        lines.append(f"[{category}]")

        added_hosts = set()

        for job in jobs:

            #
            # Use hostname or IP depending on inventory type
            #
            host_identifier = (
                job["ip"]
                if use_ip
                else job["hostname"]
            )

            if host_identifier not in added_hosts:
                lines.append(host_identifier)
                added_hosts.add(host_identifier)

        lines.append("")
    #parent group
    lines.append(f"[{parent_group}:children]")

    for category in filtered.keys():
        lines.append(category)

    lines.append("")
    #variables
    lines.append(f"[{parent_group}:vars]")

    remediation_categories = ",".join(
        sorted(filtered.keys())
    )

    lines.append(
        f"remediation_categories={remediation_categories}"
    )

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Inventory created: {filename}")

    return filename


# =========================================================
# SAVE CATEGORY JSON
# =========================================================
def save_category_json(jobs, category, folder="inventory"):

    os.makedirs(folder, exist_ok=True)

    filename = f"{folder}/{category}_jobs.json"

    with open(filename, "w") as f:
        json.dump(jobs, f, indent=4)

    print(f"[+] JSON saved: {filename}")

    return filename


# =========================================================
# SAVE REMEDIATION CONTROL
# =========================================================
def save_remediation_control(categories, filename):

    os.makedirs(os.path.dirname(filename), exist_ok=True)

    data = {
        "remediation_categories": sorted(categories)
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Control file created: {filename}")

    return filename


# =========================================================
# PUSH TO GITLAB
# =========================================================
def push_to_gitlab(local_file, gitlab_path):
    #added will remove for prod
    if DRY_RUN:
        print(f"[DRY RUN] Would upload to GitLab: {gitlab_path}")
        return
    
    if not GITLAB_URL:
        raise RuntimeError("GITLAB_URL is not configured")

    if not GITLAB_TOKEN:
        raise RuntimeError("GITLAB_TOKEN is not configured")

    if not GITLAB_PROJECT_ID:
        raise RuntimeError("GITLAB_PROJECT_ID is not configured")

    headers = {
        "PRIVATE-TOKEN": GITLAB_TOKEN
    }

    with open(local_file, "r") as f:
        content = f.read()

    encoded_path = requests.utils.quote(
        gitlab_path,
        safe=""
    )

    url = (
        f"{GITLAB_URL}/api/v4/projects/"
        f"{GITLAB_PROJECT_ID}/repository/files/"
        f"{encoded_path}"
    )

    payload = {
        "branch": GITLAB_BRANCH,
        "content": content,
        "commit_message": f"Automated remediation update: {gitlab_path}"
    }

#replace the below so as to automatically replace/overwrite files in gitlab
#    check = requests.get(
#        url,
#        headers=headers,
#        verify=False
#    )


    check_url = f"{url}?ref={GITLAB_BRANCH}"

    check = requests.get(
        check_url,
        headers=headers,
        verify=False
    )

    if check.status_code == 200:

        response = requests.put(
            url,
            headers=headers,
            json=payload,
            verify=False
        )

    else:

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=False
        )

    if response.status_code in [200, 201]:

        print(f"[+] Uploaded to GitLab: {gitlab_path}")

    else:

        FAILURES.append(f"gitlab:{gitlab_path}")
        print(
            f"FAILED upload {gitlab_path}: {response.status_code}"
        )

        print(response.text)

#sends summary emails for all teams to pvmg team
# =========================================================
# SEND EMAIL WITH ATTACHMENTS
# =========================================================
###def send_email(files, summary):

###    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

###    msg = MIMEMultipart()

###    msg["From"] = EMAIL_FROM
###    msg["To"] = ", ".join(EMAIL_TO)
###    msg["Subject"] = EMAIL_SUBJECT.format(date=date_str)

    
#Dear Team,

#The automated vulnerability reporting/remediation scan has completed.
#Please find the remediation files attached for review. Please note that the vulnerable
#assets will be patched in the next 7 days. 

#Summary
#-------
#{summary}

#Next Steps
#----------
#1. Review the attached inventory and jobs files
#2. Log into Ansible Tower
#3. Verify the scheduled remediation jobs
#4. Confirm maintenance windows before execution

#Files Attached
#--------------
#- remediation_inventory.ini
#- chrome_jobs.json
#- firefox_jobs.json
#- edge_jobs.json
#- wireshark_jobs.json
#- notepadplusplus_jobs.json
#- jabber_jobs.json
#- winrar_jobs.json
#- 7zip_jobs.json
#- winscp_jobs.json
#- java_jre_jobs.json
#- vscode_jobs.json
#- vmwaretools_jobs.json
#- silverlight_jobs.json
#- msxml4_jobs.json
#- dotnet_jobs.json
#- defender_jobs.json
##- windowsos.json
#- windowsos2016_jobs.json
#- windowsos2019_jobs.json
#- windowsos2022_jobs.json
#- CVE-2013-3900.json
#- CVE-2022-0001.json
#- W_TLS_1.0_1.1.json #
#- W_TLS_Sweet32.json
#- W_TLS_HMAC.json
#- W_TLS_StaticKeys.json
#- insecureftp
#- netbios_nbstat
#- RhelOS.json
#- R_SSH_HMAC.json
#- R_SSH_CBC.json
#- R_SSH_KEX.json
#- ICMP.json
#- remediation_control.json

#This is an automated message. Do not reply to this email.

#Regards,
#Cyber Prevent - Endpoint Security
#"""

###    body = f"""    
###Dear Team,

###The automated vulnerability reporting/remediation scan has completed.
###Please find the remediation files across all teams attached for review. Please note that the vulnerable
###assets will be AUTOMATICALLY patched in the next 14 days if no remediation effort is made.

###Summary
###-------
###{summary}

###Next Steps
###----------
###1. Review the attached inventory and jobs files.
###2. Log into Ansible Tower.
###3. Verify the scheduled remediation jobs.
###4. Confirm maintenance windows before execution.

###Files Attached
###--------------
###Windows
###--------
###- remediation_inventory.ini
###- remediation_control.json
###- Windows *_jobs.json files

###Linux
###------
###- l_remediation_inventory.ini
###- l_remediation_control.json
###- Linux *_jobs.json files

###This is an automated message. Do not reply to this email.

###Regards,
###Cyber Prevent - Endpoint Security
###"""


###    msg.attach(MIMEText(body, "plain"))

###    for filepath in files:

###        if not os.path.exists(filepath):
###            print(f"[!] File not found, skipping: {filepath}")
###            continue

###        with open(filepath, "rb") as f:

###            part = MIMEBase("application", "octet-stream")
###            part.set_payload(f.read())

###        encoders.encode_base64(part)

###        filename = os.path.basename(filepath)

###        part.add_header(
###            "Content-Disposition",
###            f"attachment; filename={filename}"
###        )

###        msg.attach(part)

###        print(f"[+] Attached: {filename}")

###    try:

###        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:

###            server.ehlo()

###            server.sendmail(
###                EMAIL_FROM,
###                EMAIL_TO,
###                msg.as_string()
###            )

###        print(f"[+] Email sent to: {', '.join(EMAIL_TO)}")

###    except Exception as e:

###ends here        print(f"FAILED sending email: {e}")


# =========================================================
# SAVE EMAIL LOCALLY FOR TESTING
# =========================================================
def save_email_locally(msg, filename):
    """
    Save a complete MIME email as an .eml file.

    This allows local testing without SMTP.
    The resulting .eml file can be opened in Outlook
    or another mail client.
    """

    os.makedirs(EMAIL_TEST_DIR, exist_ok=True)

    filepath = os.path.join(
        EMAIL_TEST_DIR,
        filename
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(msg.as_string())

    print(f"[+] Test email saved: {filepath}")

    return filepath


# =========================================================
# SEND EMAIL WITH ATTACHMENTS
# =========================================================
def send_email(files, summary, category_summary=None):

    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    msg = MIMEMultipart("alternative")

    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg["Subject"] = EMAIL_SUBJECT.format(date=date_str)

    category_summary = category_summary or []

    total_categories = len(category_summary)
    total_hosts = sum(item["count"] for item in category_summary)

    # =================================================
    # PLAIN TEXT FALLBACK
    # =================================================
    text_body = f"""
Dear Team,

The automated vulnerability reporting/remediation scan has completed.
Please find the remediation files across all teams attached for review. Please note that the vulnerable
assets will be AUTOMATICALLY patched in the next 14 days if no remediation effort is made.

Summary
-------
{summary}

Next Steps
----------
1. Review the attached inventory and jobs files.
2. Log into Ansible Tower.
3. Verify the scheduled remediation jobs.
4. Confirm maintenance windows before execution.

This is an automated message. Do not reply to this email.

Regards,
Cyber Prevent - Endpoint Security
"""

    # =================================================
    # CATEGORY SUMMARY ROWS (table-based, Outlook safe)
    # =================================================
    category_rows = ""
    for i, item in enumerate(sorted(category_summary, key=lambda x: x["category"])):

        display_name = CATEGORY_NAMES.get(item["category"], item["category"])
        count = item["count"]
        row_bg = "#ffffff" if i % 2 == 0 else "#f4f6f8"

        if count == 0:
            status_color = "#999999"
            status_text = "No vulnerabilities found"
        else:
            status_color = "#c0392b"
            status_text = f"{count} host{'s' if count != 1 else ''} affected"

        category_rows += f"""
        <tr>
           <td bgcolor="{row_bg}" style="padding:7px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:12px;color:#222222;">{display_name}</td>
           <td bgcolor="{row_bg}" style="padding:7px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:12px;color:{status_color};">{status_text}</td>
        </tr>"""

    # =================================================
    # HTML BODY
    # =================================================
    html_body = f"""\
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<!--[if mso]>
<style type="text/css">
table {{ border-collapse: collapse; }}
</style>
<![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f4f6f8;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f4f6f8;">
  <tr>
    <td align="center" style="padding:20px 0;">

      <table border="0" cellpadding="0" cellspacing="0" width="640" style="background-color:#ffffff;border:1px solid #e0e0e0;">

        <!-- HEADER -->
        <tr>
          <td bgcolor="#1e5631" style="padding:20px 24px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:11px;color:#a5d6a7;letter-spacing:1px;">
                  CYBER PREVENT - ENDPOINT SECURITY
                </td>
              </tr>
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:19px;color:#ffffff;padding-top:4px;">
                  Automated remediation report
                </td>
              </tr>
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:13px;color:#c8e6c9;padding-top:2px;">
                  {date_str}
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="padding:24px;">

            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:14px;color:#444444;line-height:1.5;padding-bottom:16px;">
                  Dear Team,<br><br>
                  The automated vulnerability reporting/remediation scan has completed.
                  Please find the remediation files across all teams attached for review.
                </td>
              </tr>
            </table>

            <!-- WARNING BANNER -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
              <tr>
                <td bgcolor="#fff4e0" style="padding:10px 14px;border-left:3px solid #e69500;font-family:Arial,sans-serif;font-size:13px;color:#7a5300;">
                  Vulnerable assets will be automatically patched in 14 days if no remediation effort is made.
                </td>
              </tr>
            </table>

            <!-- STAT CELLS -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:24px;">
              <tr>
                <td width="50%" bgcolor="#eef1f4" align="center" style="padding:14px;">
                  <span style="font-family:Arial,sans-serif;font-size:20px;color:#1e5631;font-weight:bold;">{total_categories}</span><br>
                  <span style="font-family:Arial,sans-serif;font-size:11px;color:#666666;">Categories processed</span>
                </td>
                <td width="12"></td>
                <td width="50%" bgcolor="#eef1f4" align="center" style="padding:14px;">
                  <span style="font-family:Arial,sans-serif;font-size:20px;color:#1e5631;font-weight:bold;">{total_hosts}</span><br>
                  <span style="font-family:Arial,sans-serif;font-size:11px;color:#666666;">Host-category hits</span>
                </td>
              </tr>
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:8px;">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:11px;color:#999999;letter-spacing:1px;">
                  CATEGORY SUMMARY
                </td>
              </tr>
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;margin-bottom:24px;">
              <tr bgcolor="#eef1f4">
                <td style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:11px;color:#555555;">Category</td>
                <td style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:11px;color:#555555;">Status</td>
              </tr>
              {category_rows}
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:8px;">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:11px;color:#999999;letter-spacing:1px;">
                  NEXT STEPS
                </td>
              </tr>
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:13px;color:#444444;line-height:1.7;">
                  1. Review the attached inventory and jobs files.<br>
                  2. Log into Ansible Tower.<br>
                  3. Verify the scheduled remediation jobs.<br>
                  4. Confirm maintenance windows before execution.
                </td>
              </tr>
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top:8px;border-top:1px solid #e0e0e0;">
              <tr>
                <td style="padding-top:16px;font-family:Arial,sans-serif;font-size:12px;color:#999999;">
                  This is an automated message. Do not reply to this email.<br><br>
                  Regards,<br>Cyber Prevent - Endpoint Security
                </td>
              </tr>
            </table>

          </td>
        </tr>

      </table>

    </td>
  </tr>
</table>
</body>
</html>
"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    for filepath in files:

        if not os.path.exists(filepath):
            print(f"[!] File not found, skipping: {filepath}")
            continue

        with open(filepath, "rb") as f:

            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())

        encoders.encode_base64(part)

        filename = os.path.basename(filepath)

        part.add_header(
            "Content-Disposition",
            f"attachment; filename={filename}"
        )

        msg.attach(part)

        print(f"[+] Attached: {filename}")
        
    # EMAIL DELIVERY
    if EMAIL_MODE == "file":
        filename = (
            f"remediation_report_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.eml"
        )

        save_email_locally(
            msg,
            filename
        )

        print(
            f"[+] EMAIL_MODE=file "
            f"- no SMTP connection attempted"
        )

    elif EMAIL_MODE == "smtp":

        try:

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:

                server.ehlo()

                server.sendmail(
                    EMAIL_FROM,
                    EMAIL_TO,
                    msg.as_string()
                )

            print(f"[+] Email sent to: {', '.join(EMAIL_TO)}")

        except Exception as e:

            print(f"FAILED sending email: {e}")
            FAILURES.append("email")

    else:
        print(
            f"[!] Unknown EMAIL_MODE: {EMAIL_MODE}"
        )

        print(
            "[!] Valid values are: file, smtp"
        )
#new function        
#sends emails to individual teams
# =========================================================
# SEND TEAM SUMMARY EMAIL
# =========================================================
def send_report_summary_email(report_name, assets, recipients, files=None):

    msg = MIMEMultipart("alternative")

    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = f"Remediation Summary - {report_name}"


    #
    # Build category list
    #
    category_assets = {}

    for ip, asset in assets.items():
        hostname = asset["hostname"]
        for category in asset["categories"]:
            if category == "other":
                continue
            category_assets.setdefault(category, set()).add((hostname, ip))

    total_categories = len(category_assets)
    total_assets = len(assets)

    # =================================================
    # PLAIN TEXT FALLBACK
    # =================================================
    text_body = f"Dear Team,\n\nThe latest vulnerability/remediation scan has completed.\n\n"
    text_body += f"Total categories : {total_categories}\nTotal assets     : {total_assets}\n\n"

    for category in sorted(category_assets.keys()):
        display_name = CATEGORY_NAMES.get(category, category)
        text_body += f"\n{display_name}\n" + "-" * len(display_name) + "\n"
        for hostname, ip in sorted(category_assets[category]):
            text_body += f"{hostname} ({ip})\n"

    text_body += "\n\nRegards,\nCyber Prevent - Endpoint Security\n"

    # =================================================
    # CATEGORY BLOCKS (table-based, Outlook safe)
    # =================================================
    category_blocks = ""

    for category in sorted(category_assets.keys()):

        display_name = CATEGORY_NAMES.get(category, category)
        hosts = sorted(category_assets[category])

        host_rows = ""
        for i, (hostname, ip) in enumerate(hosts):
            row_bg = "#ffffff" if i % 2 == 0 else "#f4f6f8"
            host_rows += f"""
            <tr>
              <td bgcolor="{row_bg}" style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:12px;color:#222222;">{hostname}</td>
              <td bgcolor="{row_bg}" style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:12px;color:#555555;">{ip}</td>
            </tr>"""

        category_blocks += f"""
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:16px;border-collapse:collapse;">
          <tr>
            <td bgcolor="#1e5631" style="padding:8px 12px;font-family:Arial,sans-serif;font-size:13px;color:#ffffff;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="font-family:Arial,sans-serif;font-size:13px;color:#ffffff;">{display_name}</td>
                  <td align="right" style="font-family:Arial,sans-serif;font-size:12px;color:#c8e6c9;">{len(hosts)} host{'s' if len(hosts) != 1 else ''}</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td>
              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;">
                <tr bgcolor="#eef1f4">
                  <td style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:11px;color:#555555;">Hostname</td>
                  <td style="padding:6px 12px;border:1px solid #dddddd;font-family:Arial,sans-serif;font-size:11px;color:#555555;">IP address</td>
                </tr>
                {host_rows}
              </table>
            </td>
          </tr>
        </table>"""

    # =================================================
    # HTML BODY (table-based layout, inline styles only)
    # =================================================
    html_body = f"""\
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<!--[if mso]>
<style type="text/css">
table {{ border-collapse: collapse; }}
</style>
<![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f4f6f8;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f4f6f8;">
  <tr>
    <td align="center" style="padding:20px 0;">

      <table border="0" cellpadding="0" cellspacing="0" width="640" style="background-color:#ffffff;border:1px solid #e0e0e0;">

        <!-- HEADER -->
        <tr>
          <td bgcolor="#1e5631" style="padding:20px 24px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:11px;color:#a5d6a7;letter-spacing:1px;">
                  CYBER PREVENT - ENDPOINT SECURITY
                </td>
              </tr>
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:19px;color:#ffffff;padding-top:4px;">
                  Remediation summary
                </td>
              </tr>
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:13px;color:#c8e6c9;padding-top:2px;">
                  {report_name}
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="padding:24px;">

            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:14px;color:#444444;line-height:1.5;padding-bottom:16px;">
                  Dear Team,<br><br>
                  The latest vulnerability scan has completed. Assets below are grouped by remediation category.
                </td>
              </tr>
            </table>

            <!-- WARNING BANNER -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
              <tr>
                <td bgcolor="#fff4e0" style="padding:10px 14px;border-left:3px solid #e69500;font-family:Arial,sans-serif;font-size:13px;color:#7a5300;">
                  Unremediated assets will be automatically patched in 14 days.
                </td>
              </tr>
            </table>

            <!-- STAT CELLS -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:24px;">
              <tr>
                <td width="50%" bgcolor="#eef1f4" align="center" style="padding:14px;">
                  <span style="font-family:Arial,sans-serif;font-size:20px;color:#1e5631;font-weight:bold;">{total_categories}</span><br>
                  <span style="font-family:Arial,sans-serif;font-size:11px;color:#666666;">Categories affected</span>
                </td>
                <td width="12"></td>
                <td width="50%" bgcolor="#eef1f4" align="center" style="padding:14px;">
                  <span style="font-family:Arial,sans-serif;font-size:20px;color:#1e5631;font-weight:bold;">{total_assets}</span><br>
                  <span style="font-family:Arial,sans-serif;font-size:11px;color:#666666;">Total assets</span>
                </td>
              </tr>
            </table>

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:10px;">
              <tr>
                <td style="font-family:Arial,sans-serif;font-size:11px;color:#999999;letter-spacing:1px;">
                  AFFECTED CATEGORIES
                </td>
              </tr>
            </table>

            {category_blocks}

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top:8px;border-top:1px solid #e0e0e0;">
              <tr>
                <td style="padding-top:16px;font-family:Arial,sans-serif;font-size:12px;color:#999999;">
                  This is an automated message. Do not reply to this email.<br><br>
                  Regards,<br>Cyber Prevent - Endpoint Security
                </td>
              </tr>
            </table>

          </td>
        </tr>

      </table>

    </td>
  </tr>
</table>
</body>
</html>
"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    for filepath in (files or []):
        if not os.path.exists(filepath):
            print(f"[!] File not found, skipping: {filepath}")
            continue
        with open(filepath, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        filename = os.path.basename(filepath)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(part)
        print(f"[+] Attached: {filename}")
    if EMAIL_MODE == "file":

        safe_report_name = re.sub(
            r"[^A-Za-z0-9_-]+",
            "_",
            report_name
        )

        filename = (
            f"team_{safe_report_name}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.eml"
        )

        save_email_locally(
            msg,
            filename
        )

        print(
            f"[+] Team email saved locally "
            f"for {report_name}"
        )

    elif EMAIL_MODE == "smtp":
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.sendmail(EMAIL_FROM, recipients, msg.as_string())
            print(f"[+] Team summary email sent to {', '.join(recipients)}")
        except Exception as e:
            print(f"FAILED sending team email: {e}")
            FAILURES.append("email")
    else:
        print(
            f"[!] Unknown EMAIL_MODE: {EMAIL_MODE}"
        )


#=========================================================
# SAVE SUMMARY JSON
#=========================================================
def write_summary(report_asset_map, all_category_jobs, generated_files, report_inventory_files):
    categories = []
    for cat, jobs in sorted(all_category_jobs.items()):
        sev = {}
        for j in jobs:
            sev[j["severity"]] = sev.get(j["severity"], 0) + 1
        categories.append({
            "category": cat,
            "display_name": CATEGORY_NAMES.get(cat, cat),
            "platform": "windows" if cat in WINDOWS_CATEGORIES else "linux",
            "hosts": len(jobs),
            "severity": sev,
        })
    summary = {
        "dry_run": DRY_RUN,
        "reports": [
            {"report_id": rid,
             "team": REPORT_EMAILS.get(rid, {}).get("team", rid),
             "assets": len(a)}
            for rid, a in report_asset_map.items()
        ],
        "categories": categories,
        "files": [os.path.relpath(f) for f in generated_files],
        "team_files": {rid: [os.path.relpath(f) for f in fs]
                       for rid, fs in report_inventory_files.items()},
        "failures": FAILURES,
    }
    with open("summary.json", "w") as f:
        json.dump(summary, f, indent=2)


#=========================================================



# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":

    # =====================================================
    # PROCESS ALL REPORT IDS
    # =====================================================

    assets = {}

    #
    # Stores assets per report
    #
    report_asset_map = {}


    for report_id in REPORT_IDS:

        print(f"\n{'=' * 70}")
        print(f"Processing Report ID: {report_id}")
        print(f"{'=' * 70}")

        content = download_report(
            IVM_URL,
            IVM_USER,
            IVM_PASS,
            report_id
        )

        if not content:
            print(f"Skipping Report ID {report_id}")
            continue

        report_assets = extract_assets(content)

        # Keep assets for this report only
#
        report_asset_map[report_id] = copy.deepcopy(report_assets)

        #
        # Merge assets from this report into the master asset list
        #
        for ip, data in report_assets.items():

            if ip not in assets:

                assets[ip] = copy.deepcopy(data)

            else:

                for category, vulns in data["categories"].items():

                    if category not in assets[ip]["categories"]:
                        assets[ip]["categories"][category] = []
                    existing = {
                        (
                            v["title"],
                            v["severity"],
                            v["solution"]
                        )
                        for v in assets[ip]["categories"][category]
                    }

                    for vuln in vulns:

                        key = (
                            vuln["title"],
                            vuln["severity"],
                            vuln["solution"]
                        )

                        if key not in existing:
                            assets[ip]["categories"][category].append(vuln)
                            existing.add(key)
                    

    if not assets:
        print("No assets were extracted from any report.")
        sys.exit(1)

    detected_categories = set()

    for ip, asset_data in assets.items():

        for category in asset_data["categories"].keys():

            if category != "other":
                detected_categories.add(category)

    remediation_categories = sorted(
        list(detected_categories)
    )

    print(
        f"[+] Detected remediation categories: "
        f"{', '.join(remediation_categories)}"
    )

    # =====================================================
    # TRACK GENERATED FILES
    # =====================================================
    generated_files = []

    summary_lines = []

    category_summary_data = []

    all_category_jobs = {}

    # =====================================================
    # PROCESS EACH CATEGORY
    # =====================================================
    for category in remediation_categories:

        jobs = build_category_jobs(
            assets,
            category
        )

        if not jobs:

            print(
                f"No vulnerabilities found "
                f"for category: {category}"
            )

            summary_lines.append(
                f"- {category.upper()}: No vulnerabilities found"
            )

            category_summary_data.append({          # <-- ADD THIS BLOCK
                "category": category,
                "count": 0
            })

            continue

        all_category_jobs[category] = jobs

        summary_lines.append(
            f"- {category.upper()}: "
            f"{len(jobs)} host(s) affected"
        )

        category_summary_data.append({               # <-- ADD THIS BLOCK
            "category": category,
            "count": len(jobs)
        })

        # =================================================
        # SAVE CATEGORY JSON
        # =================================================
        folder = (
            "inventory"
            if category in WINDOWS_CATEGORIES
            else "l_inventory"
        )

        json_file = save_category_json(
            jobs,
            category,
            folder
        )

        generated_files.append(json_file)
        # =================================================
        # PUSH CATEGORY JSON TO GITLAB
        # =================================================
        # if category in WINDOWS_CATEGORIES:
        #     gitlab_json_path = f"inventory/{category}_jobs.json"
        # else:
        #     gitlab_json_path = f"l_inventory/{category}_jobs.json"

        # push_to_gitlab(
        #     json_file,
        #     gitlab_json_path
        # )

    # =====================================================
    # WINDOWS INVENTORY
    # =====================================================
    # =====================================================
    #windows_inventory = create_inventory(
    #    all_category_jobs,
    #    "inventory/remediation_inventory.ini",
    #    "all_windows",
    #    WINDOWS_CATEGORIES
    #)
    #OR
    windows_inventory = create_inventory(
        category_jobs=all_category_jobs,
        filename="inventory/remediation_inventory.ini",
        parent_group="all_windows",
        valid_categories=WINDOWS_CATEGORIES,
        use_ip=False
    )

    generated_files.append(windows_inventory)

    push_to_gitlab(
        windows_inventory,
        "inventory/remediation_inventory.ini"
    )

    # =====================================================
    # LINUX INVENTORY
    # =====================================================

    #linux_inventory = create_inventory(
    #    all_category_jobs,
    #    "l_inventory/l_remediation_inventory.ini",
    #    "linux",
    #    LINUX_CATEGORIES
    #)
#OR
    linux_inventory = create_inventory(
        category_jobs=all_category_jobs,
        filename="l_inventory/l_remediation_inventory.ini",
        parent_group="linux",
        valid_categories=LINUX_CATEGORIES,
        use_ip=True
    )

    generated_files.append(linux_inventory)

    push_to_gitlab(
        linux_inventory,
        "l_inventory/l_remediation_inventory.ini"
    )


    # =====================================================
    # CREATE WINDOWS REMEDIATION CONTROL
    # =====================================================
    windows_categories = [
        c for c in remediation_categories
        if c in WINDOWS_CATEGORIES
    ]

    windows_control = save_remediation_control(
        windows_categories,
        "inventory/remediation_control.json"
    )

    generated_files.append(windows_control)

   # push_to_gitlab(
   #     windows_control,
   #     "inventory/remediation_control.json"
   # )

    # =====================================================
    # CREATE LINUX REMEDIATION CONTROL
    # =====================================================
    linux_categories = [
        c for c in remediation_categories
        if c in LINUX_CATEGORIES
    ]

    linux_control = save_remediation_control(
        linux_categories,
        "l_inventory/l_remediation_control.json"
    )

    generated_files.append(linux_control)

   # push_to_gitlab(
   #     linux_control,
   #     "l_inventory/l_remediation_control.json"
   # )


        # =====================================================
    # PER-REPORT (PER-TEAM) INVENTORY FILES
    # =====================================================
    report_inventory_files = {}   # report_id -> list of generated files

    for report_id, report_assets_data in report_asset_map.items():

        team = REPORT_EMAILS.get(report_id, {}).get("team", report_id)
        team_slug = team.lower().replace(" ", "_")

        report_categories = set()

        for ip, asset_data in report_assets_data.items():
            for category in asset_data["categories"].keys():
                if category != "other":
                    report_categories.add(category)

        report_category_jobs = {}

        for category in report_categories:
            jobs = build_category_jobs(report_assets_data, category)
            if jobs:
                report_category_jobs[category] = jobs

        if not report_category_jobs:
            print(f"[!] No categorized vulnerabilities for report {report_id}, skipping")
            continue

        report_files = []

        if any(c in WINDOWS_CATEGORIES for c in report_category_jobs):

            windows_ini = create_inventory(
                category_jobs=report_category_jobs,
                filename=f"inventory/{team_slug}_remediation_inventory.ini",
                parent_group="all_windows",
                valid_categories=WINDOWS_CATEGORIES,
                use_ip=False
            )

            report_files.append(windows_ini)

            push_to_gitlab(
                windows_ini,
                f"inventory/{team_slug}_remediation_inventory.ini"
            )

        if any(c in LINUX_CATEGORIES for c in report_category_jobs):

            linux_ini = create_inventory(
                category_jobs=report_category_jobs,
                filename=f"l_inventory/{team_slug}_l_remediation_inventory.ini",
                parent_group="linux",
                valid_categories=LINUX_CATEGORIES,
                use_ip=True
            )

            report_files.append(linux_ini)

            push_to_gitlab(
                linux_ini,
                f"l_inventory/{team_slug}_l_remediation_inventory.ini"
            )

        report_inventory_files[report_id] = report_files


        

    # =====================================================
    # SEND EMAIL
    # =====================================================
    print("[+] Sending remediation report email...")
    summary = "\n".join(summary_lines) if summary_lines else "No data"
    send_email(generated_files, summary, category_summary_data)

    #print("\n[+] Remediation automation completed")
    #print("[!] Tower patching runs on its configured schedule.")

    # =====================================================
    # SEND TEAM SUMMARY EMAILS
    # =====================================================
    for report_id, team_assets in report_asset_map.items():

        if report_id not in REPORT_EMAILS:
            continue

        send_report_summary_email(
            report_name=REPORT_EMAILS[report_id]["team"],
            assets=team_assets,
            recipients=REPORT_EMAILS[report_id]["emails"],
            files=report_inventory_files.get(report_id, []) #added later
        )

    print("\n[+] Remediation automation completed")
    print("[!] Tower patching runs on its configured schedule.")
    
    # =====================================================
    # WRITE SUMMARY JSON    
    write_summary(report_asset_map, all_category_jobs, generated_files, report_inventory_files)
    if FAILURES:
        print(f"[!] Completed with failures: {FAILURES}")
        sys.exit(1)