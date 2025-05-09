#!/usr/bin/env python3
import nmap
import yaml
import requests
import json
import time
import logging

# Configuring logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def load_config(path="config.yaml"):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def run_nmap_scan(target, ports):
    nm = nmap.PortScanner()
    logging.info(f"Scanning target {target} on ports {ports}")
    nm.scan(hosts=target, ports=ports, arguments='-sV')
    return nm

def parse_scan_results(nm):
    events = []
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    for host in nm.all_hosts():
        if nm[host].state() != 'up':
            continue
        open_ports = []
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                open_ports.append({
                    'port': port,
                    'protocol': proto,
                    'service': data.get('name'),
                    'product': data.get('product'),
                    'version': data.get('version')
                })
        events.append({
            'timestamp': timestamp,
            'host': host,
            'state': nm[host].state(),
            'open_ports': open_ports
        })
    return events

def send_to_splunk(events, splunk_url, token):
    headers = {
        'Authorization': f'Splunk {token}',
        'Content-Type': 'application/json'
    }
    for event in events:
        payload = {'event': event}
        try:
            resp = requests.post(splunk_url, headers=headers, json=payload, timeout=10)
            resp.raise_for_status()
            logging.info(f"Sent event for {event['host']} to Splunk")
        except requests.RequestException as e:
            logging.error(f"Failed to send to Splunk: {e}")

def main():
    config = load_config()
    splunk_cfg = config.get('splunk', {})
    scan_cfg = config.get('scan', {})
    targets = scan_cfg.get('targets', [])
    ports = scan_cfg.get('ports', '')

    for target in targets:
        nm = run_nmap_scan(target, ports)
        events = parse_scan_results(nm)
        send_to_splunk(events, splunk_cfg['url'], splunk_cfg['token'])

if __name__ == "__main__":
    main()
