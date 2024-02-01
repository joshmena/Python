import datetime
import hmac
import hashlib
import encodings
import subprocess
import requests
import json
import csv

def make_token_request(host, call, publicToken, privateToken):
    time = str(datetime.datetime.utcnow())
    signature = hmac.new(privateToken.encode('ASCII'), msg=(call+"\n"+publicToken+"\n"+time).encode('ASCII'), digestmod=hashlib.sha1).hexdigest()
    header = {"DTAPI-token":publicToken,"DTAPI-date":time,"DTAPI-Signature":signature}
    response = requests.get(host + call, headers=header, verify=False)
    clean_response = json.loads(response.content)
    with open('DarkTrace_IPs.csv', 'w+', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['Source IP','Destination IP','Port'])
        writer.writeheader()
        for event in clean_response:
            source_ip = ''
            destination_ip = ''
            port = ''
            for component in event['triggeredComponents']:
                for trigs_filter in component['triggeredFilters']:
                    if trigs_filter['id'] == 'd1':
                        source_ip = trigs_filter['trigger']['value']
                    elif trigs_filter['id'] == 'd5':
                        destination_ip = trigs_filter['trigger']['value']
                    elif trigs_filter['id'] == 'd6':
                        port = trigs_filter['trigger']['value']     
            row = {
                'Source IP':source_ip,
                'Destination IP':destination_ip,
                'Port':port
            }       
            writer.writerow(row)               
        
def get_dark_trace_data(date):
    date_to_pass = '/modelbreaches?from={}&pid=999'.format(date)
    make_token_request('https://10.10.10.10',date_to_pass,'f551440eb87f8er1af6175437e9aedba5f7c8bf75','igie48ebe7586e121138988f1a6eb3886206ma86f5')

get_dark_trace_data('2023-05-07')
