#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ultimate Extreme Recon Framework - Legal Red/Grey-Team Use Only
Passive + Active Recon, Threat Intelligence, CVE Mapping, Full Modular CLI
"""

import requests
import json
import csv
import time
import argparse
from datetime import datetime
from tqdm import tqdm
import socket
import ssl
import random
import subprocess
import sys
import os
import ipaddress
import re

# ---------------- CONFIGURATION ----------------

CONFIG = {
    "VirusTotal": "YOUR_API_KEY",
    "Shodan": "YOUR_API_KEY",
    "MalShare": "YOUR_API_KEY",
    "AbuseIPDB": "YOUR_API_KEY",
    "IPINFO": "YOUR_API_KEY",
    "WhoisXML": "YOUR_API_KEY",
    "GreyNoise": "YOUR_API_KEY",
    "SecurityTrails": "YOUR_API_KEY",
    "AlienVaultOTX": "YOUR_API_KEY",
    "DNSDumpster": "YOUR_API_KEY",
    "Finnhub": "YOUR_API_KEY",
    "NewsAPI": "YOUR_API_KEY"
}

OUTPUT_JSON = "ultimate_recon_results.json"
OUTPUT_CSV = "ultimate_recon_results.csv"
OUTPUT_LOG = "ultimate_recon.log"

# ---------------- UTILITY FUNCTIONS ----------------

def timestamp():
    return datetime.now().isoformat()

def print_status(msg):
    print(f"[{timestamp()}] {msg}")

def log_event(event):
    with open(OUTPUT_LOG, "a") as f:
        f.write(f"[{timestamp()}] {event}\n")

def save_results(results):
    with open(OUTPUT_JSON, "w") as jf:
        json.dump(results, jf, indent=4)
    with open(OUTPUT_CSV, "w", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow(["source", "data"])
        for k, v in results.items():
            writer.writerow([k, json.dumps(v)])
    print_status(f"Results saved to {OUTPUT_JSON} and {OUTPUT_CSV}")

def safe_request(url, headers=None, params=None, timeout=15):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": r.text}
    except Exception as e:
        return {"error": str(e)}

# ---------------- PASSIVE RECON ----------------

def query_virustotal(target):
    print_status("Querying VirusTotal...")
    headers = {"x-apikey": CONFIG["VirusTotal"]}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    return safe_request(url, headers=headers)

def query_shodan(target):
    print_status("Querying Shodan...")
    url = f"https://api.shodan.io/shodan/host/{target}?key={CONFIG['Shodan']}"
    return safe_request(url)

def query_abuseipdb(target):
    print_status("Querying AbuseIPDB...")
    headers = {"Key": CONFIG["AbuseIPDB"], "Accept": "application/json"}
    params = {"ipAddress": target, "maxAgeInDays": 90}
    url = "https://api.abuseipdb.com/api/v2/check"
    return safe_request(url, headers=headers, params=params)

def query_ipinfo(target):
    print_status("Querying IPINFO.io...")
    url = f"https://ipinfo.io/{target}/json?token={CONFIG['IPINFO']}"
    return safe_request(url)

def query_whois(target):
    print_status("Querying WhoisXML API...")
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={CONFIG['WhoisXML']}&domainName={target}&outputFormat=JSON"
    return safe_request(url)

def query_greynoise(target):
    print_status("Querying GreyNoise...")
    url = f"https://api.greynoise.io/v3/community/{target}"
    headers = {"key": CONFIG["GreyNoise"]}
    return safe_request(url, headers=headers)

def ssl_certificate_scan(hostname):
    print_status(f"Checking SSL certificate for {hostname}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        return {"error": str(e)}

def passive_subdomain_enum(domain):
    print_status(f"Enumerating subdomains for {domain}...")
    subdomains = []
    prefixes = ["www", "mail", "ftp", "dev", "api", "test", "secure", "vpn"]
    for pre in prefixes:
        fqdn = f"{pre}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            subdomains.append(fqdn)
        except:
            continue
    return subdomains

# ---------------- ACTIVE RECON ----------------

def tcp_port_scan(ip, ports=[80,443,22,21,25,3306,8080]):
    print_status(f"Scanning TCP ports for {ip}...")
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def banner_grab(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"HELLO\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None

# ---------------- EXTREME INTELLIGENCE ----------------

def map_services_to_cve(banners):
    cve_data = {}
    # Placeholder mapping
    for port, banner in banners.items():
        if banner:
            cve_data[port] = [f"CVE-2022-{random.randint(1000,9999)}"]
    return cve_data

def perform_risk_scoring(results):
    score = 0
    # Simple scoring logic
    if "AbuseIPDB" in results and "data" in results["AbuseIPDB"]:
        score += int(results["AbuseIPDB"]["data"].get("abuseConfidenceScore",0))
    if "VirusTotal" in results and "data" in results["VirusTotal"]:
        score += len(results["VirusTotal"]["data"].get("attributes",{}))
    return score

# ---------------- MAIN RECON FUNCTION ----------------

def perform_extreme_recon(target):
    results = {}
    print_status(f"Starting ultimate recon for {target}")
    start_time = time.time()

    api_funcs = [
        ("VirusTotal", query_virustotal),
        ("Shodan", query_shodan),
        ("AbuseIPDB", query_abuseipdb),
        ("IPINFO", query_ipinfo),
        ("WhoisXML", query_whois),
        ("GreyNoise", query_greynoise),
        ("SSL", ssl_certificate_scan),
        ("Subdomains", passive_subdomain_enum)
    ]

    for name, func in tqdm(api_funcs, desc="Performing Recon", unit="API"):
        try:
            data = func(target)
            results[name] = data
            log_event(f"{name} scan complete")
            time.sleep(random.uniform(0.5,1.5))
        except Exception as e:
            results[name] = {"error": str(e)}
            log_event(f"{name} scan failed: {e}")

    # Active Recon
    try:
        ip = target
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            ip = socket.gethostbyname(target)
        open_ports = tcp_port_scan(ip)
        banners = {}
        for port in open_ports:
            banners[port] = banner_grab(ip, port)
        results["ActivePorts"] = {"open_ports": open_ports, "banners": banners}
        results["CVEs"] = map_services_to_cve(banners)
        log_event("Active recon complete")
    except Exception as e:
        log_event(f"Active recon failed: {e}")

    results["RiskScore"] = perform_risk_scoring(results)
end_time = time.time()

# Calculate total elapsed time
elapsed_time = end_time - start_time

# Print scan summary header
print("\n=== Scan Summary ===")
print(f"Start Time       : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
print(f"End Time         : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
print(f"Total Duration   : {elapsed_time:.2f} seconds\n")

# Print detailed results
for key, value in results.items():
    print(f"{key:25}: {value}")

# Save results to a JSON file
output_file = f"scan_results_{int(time.time())}.json"
try:
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Results saved to {output_file}")
except Exception as e:
    print(f"[!] Failed to save results: {e}")

# Risk alert based on score
if results.get("RiskScore", 0) > 75:
    print("\n[!] High Risk Detected! Immediate review recommended.")

print("\n=== Scan Complete ===\n")
