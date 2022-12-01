import json
import os
import urllib3

import requests
from requests.exceptions import Timeout
from flask import Flask, abort, flash, jsonify, redirect, render_template,request,session
from datetime import date,datetime,timedelta
from schemas import DashboardTileDataSchema, DashboardTileSchema
from utils import get_json, get_jwt, jsonify_data
from crayons import red,green,blue,yellow,magenta,cyan
from tile_data_formats  import *


# remove certificate warnings
urllib3.disable_warnings()

    # URL params for calls
center_token = "ics-65024d2f766a314620a7fcdeb7d95f44bb2f5ec8-aea0f5dcd40b79790dd187d38e8805d042d83392"
center_ip = "172.16.0.235"
center_port = 443
center_base_urlV3 = "api/3.0"
center_base_urlV1 ="api/1.0"
center_api_construct_event = 'event'
center_api_construct_risk = 'dashboard/risk-score/devices/counts'
center_api_construct_events_counts = 'dashboard/vulnerabilities/counts'
center_api_construct_event_cat = 'dashboard/events/categories'

    # Calculate date 30 days ago for URL queries
current_date = date.today().isoformat()
thirty_days_ago = (date.today()-timedelta(days=30)).isoformat()
    
    # Set up  various query strings for the calls
    # params_crit = {'limit': '2000', 'start': '2022-01-01', 'severity': 'veryhigh','severity':'high','category':'Control System Events','category':'Signature Based Detection','category':'Anomaly Detection'}
    # params_crit = {'limit': '2000', 'start': '2022-01-01','severity':'high','severity':'veryhigh','category':'security'}
    # params_crit = {'limit':'2000','category':'Cisco Cyber Vision Administration','category':'Security Events','category':'Anomaly Detection'}
query_string1 = {'limit':'2000','start':thirty_days_ago}
#This is concatentated with the query string to provide 2 category types... 
query_string2 = {'limit':'2000','category':'Cisco Cyber Vision Operations'}
# query_string2 = {'limit':'2000','severity':'veryhigh','category':'Security Events'}
query_string3 = {'limit': '2000', 'start': thirty_days_ago, 'end': ''}

    #  Main events call for dashboard numbers for previous 30 days
def get_events():

    #  Main events call for dashboard numbers for previous 30 days
        try:
            headers = { "x-token-id": center_token }
            r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_urlV1}/{center_api_construct_event}?category=Security%20Events&category=Cisco%20Cyber%20Vision%20Operations&category=Cisco%20Cyber%20Vision%20Administration",params=query_string1,headers=headers,verify=False, timeout = 6)
    # r_get.raise_for_status() #if there are any request errors
        except Timeout:
            print (red('we timed out on URL! - check IP address is live!'+'\n'))
        else:
            raw_json_data = r_get.json()
            # print(type(raw_json_data))
            # print(json.dumps(raw_json_data,indent = 2))
            # Extract events totals and calculate and apply 30 day window
            ev_start = (query_string1['start'])
            ev_low = (len([val for data in  raw_json_data for val in data.values() if val == 'Low']))
            ev_medium = (len([val for data in raw_json_data for val in data.values() if val == 'Medium']))
            ev_high = (len([val for data in raw_json_data for val in data.values() if val == 'High']))
            ev_veryhigh = (len([val for data in raw_json_data for val in data.values() if val == 'Very High']))

        return (ev_start ,ev_low,ev_medium,ev_high,ev_veryhigh) 

  
def get_risk_count():
        try:
            headers = { "x-token-id": center_token }
            r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_urlV3}/{center_api_construct_risk}",headers=headers,verify=False)
            r_get.raise_for_status() #if there are any request errors
            #raw JSON data response
            # raw_json_data = r_get.json()
            # print(red(raw_json_data)) 
            # return(raw_json_data)
        
        except Exception as e:
            return f"Error when connecting: {e}"
  

def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})

def pull_token():
    scheme, pull_token = request.headers['Authorization'].split()
    assert scheme.lower() == 'bearer'
    return pull_token

 
app = Flask(__name__)

@app.route('/')
def test0():
    return "<h1>RELAY MODULE IS UP</h1>"
    
    
@app.route('/test')
def test():
    truc = 2 + 40
    return "<h1>Sounds Good the server is UP "+str(truc)+"</h1>"
    

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html'), 404 

@app.route("/tiles", methods=["POST"])
def tiles():    
    return jsonify_data(
        [
            {
                "id": "event-count",
                "type": "metric_group",
                "title": "Cyber Vision Events by Category",
                "periods": ["last_30_days"],
                "short_description": "CV Events",
                "description": "Cyber Vision Events for the last 30 days - similar to the Events Dashboard",
                "tags": ["Cyber Vision"],
            },
            {
                "id": "risk-count",
                "type": "donut_graph",
                "title": "Cyber Vision Risk Values by Category",
                "periods": ["last_30_days"],
                "short_description": "Cyber Vision Risks",
                "description": "Cyber Vision Risk numbers - similar to the Risk Main Menu Donut",
                "tags": ["Cyber Vision"],
            },

        ]
    )
    
@app.route("/tiles/tile-data", methods=["POST"])
#extract and insert data into the tile..
def tile_data():
    #set a default token to forward..
    auth = center_token
    #use the pulled token from incoming request from secure call and compare with existing
    pulled_token = pull_token()
    if auth  == pulled_token:
        #removed the validation part - here just hard code the tile to push data to based on tile data
        data = {'tile_id':'event-count'}
        if data["tile_id"] == "event-count":

        #send the URL forward and extract the returned data values for the tile
            start , low, medium, high, veryhigh = get_events()
        # send  data to be formatted for the tile..  
        return jsonify_data(metric_tile_data_format(start , low , medium , high , veryhigh))

    data = {'tile_id':'risk-count'}
    if data['tile-id'] =='risk-count':
        print(get_risk_count())

    else: 
        print ('ITS NOT')
         

@app.route('/health', methods=['POST'])
def health():   
    data = {'status': 'ok'}
    return jsonify({'data': data})    
    
if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(port=5577,debug=True)
    