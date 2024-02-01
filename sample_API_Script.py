import requests
import os
import json
import urllib3
import csv

def read_hosts():
    with open("C:\\BUILDS\\SITES\\testips.txt") as file_in:
        ips = []
        for ip in file_in:
            clean_ip = ip.strip("\n")
            ips.append(clean_ip)
    return(ips)

def generate_token():
    headers = {
        'Content-type': 'application/json',
    }

    data = '{"userName": "tokenhere", "password": "hashkey=="}'   

    response = requests.post('https://xx.xx.xx.xx:8443/api/auth/login', headers=headers, data=data, verify=False)
    clean = response.json()
    return str(clean['sessionKey'])

def get_events(sessionKey):
    headers = {
        'Content-type': 'application/json',
        'Sessionkey': sessionKey
    }

    data = '{"timestampStart":"now-6h","timestampEnd":"now","attackerIp":["1.1.1.7"],"severity_start":1,"severity_end":15}'
    response = requests.post('https://xx.xx.xx.xx:8443/api/eventsquery/alerts',headers=headers, data=data, verify=False)
    clean_output = response.json()
    ips = read_hosts()
    tested_ips = []
    tested_targets = {}
    with open('Succesfull_Decoy_Ips.csv', 'w+', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['Sucessfull Decoy IPs','Ports','VLAN','Attack Name','Attack Description'])
        writer.writeheader()
        for ip in clean_output['eventdata'][0]['allARPScanIPs']:
            tested_ips.append(ip)
        for event in clean_output['eventdata']:
            attack_descriptions = event['attackDesc']
            attack_name = event['attackName']
            vlan = event['details']['VLAN']
            port = ""
            if "Port" in event['attackDesc']:
                result = event['attackDesc'].split('=')
                port_number = result[4].split()
                port = port_number[0]
            elif "at [" in event['attackDesc']:
                result = event['attackDesc'].split()
                port_text = result[9].split(':')
                clean_port = port_text[1][:-2]
                port = clean_port
            for ip in tested_ips:
                row = {'Sucessfull Decoy IPs':ip,'VLAN':vlan,'Ports':port,'Attack Name':attack_name,'Attack Description': attack_descriptions} 
                writer.writerow(row)   
    with open('Failed_Decoy_IPs.csv', 'w+', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['Failed Decoy IPs'])
        writer.writeheader()                
        for ip in ips:
            if ip not in tested_ips:
                untestedrow = {
                    'Failed Decoy IPs':ip
                }
                writer.writerow(untestedrow)                   
                 
def retrieve_events():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    a = generate_token()
    get_events(a)

retrieve_events()    
