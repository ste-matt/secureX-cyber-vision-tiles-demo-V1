import json
import os
import urllib3

import requests
from flask import Flask, abort, flash, jsonify, redirect, render_template,request,session
from datetime import date,datetime,timedelta
from schemas import DashboardTileDataSchema, DashboardTileSchema
from utils import get_json, get_jwt, jsonify_data
from crayons import red,green,blue,yellow,magenta,cyan


# remove certificate warnings
urllib3.disable_warnings()

    # URL params for calls
center_token = "ics-becf2ba10ba7058ffb9651d69df46e8131090c22-d96b3d752a2899c4c4a0895076e944df49005ccb"
center_ip = "172.16.0.140"
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
query_string2 = {'limit':'2000','severity':'veryhigh','category':'Security Events'}
query_string3 = {'limit': '2000', 'start': thirty_days_ago, 'end': ''}

    #  Main events call for dashboard numbers for previous 30 days
def get_events():
        try:
            headers = { "x-token-id": center_token }
            r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_urlV1}/{center_api_construct_event}?",params=query_string1,headers=headers,verify=False)
            r_get.raise_for_status() #if there are any request errors
            raw_json_data = r_get.json()
            # Extract events totals and calculate and apply 30 day window
            ev_start = (query_string1['start'])
            ev_low = (len([val for data in  raw_json_data for val in data.values() if val == 'Low']))
            ev_medium = (len([val for data in raw_json_data for val in data.values() if val == 'Medium']))
            ev_high = (len([val for data in raw_json_data for val in data.values() if val == 'High']))
            ev_veryhigh = (len([val for data in raw_json_data for val in data.values() if val == 'Very High']))

            return (ev_start ,ev_low,ev_medium,ev_high,ev_veryhigh) 

        except Exception as e:
            return f"Error when connecting: {e}"
  
def get_risk_count():
        try:
            headers = { "x-token-id": center_token }
            r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_urlV3}/{center_api_construct_risk}",headers=headers,verify=False)
            r_get.raise_for_status() #if there are any request errors
            #raw JSON data response
            raw_json_data = r_get.json()
            print(red(raw_json_data)) 
            # return(raw_json_data)
        
        except Exception as e:
            return f"Error when connecting: {e}"
  

def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})
 
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
                "description": "Cyber Vision Risk numbers - similar to the Risk Main Menu Donut",
                "periods": ["last_30_days"],
                "tags": ["Cyber Vision"],
                "type": "donut_graph",
                "short_description": "Cyber Vision Risks",
                "title": "Cyber Vision Risk Values by Category",
                "default_period": "last_30_days",
                "id": "risk-count"
            },

        ]
    )
    
@app.route("/tiles/tile-data", methods=["POST"])
def tile_data():
    auth = get_jwt() 
    # auth = 'apples'
    if auth == "ics-becf2ba10ba7058ffb9651d69df46e8131090c22-d96b3d752a2899c4c4a0895076e944df49005ccb":
        print(red(f'authentication in APP ={auth}'))
        # data = get_json(DashboardTileSchema())
        data = {'tile_id':'event-count'}
        # print (green(data["tile_id"],bold=True))     
        if data["tile_id"] == "event-count":
            start , low, medium, high, veryhigh = get_events()
        get_risk_count()    


        return jsonify_data(
            {
                    "observed_time": {
                        "start_time": "2020-12-19T00:07:00.000Z",
                        "end_time": "2021-01-18T00:07:00.000Z",
                    },
                    "valid_time": {
                        "start_time": "2021-01-18T00:07:00.000Z",
                        "end_time": "2021-01-18T00:12:00.000Z",
                    },
                    "data": [
                        {
                            "icon": "clock",
                            "label": "Since",
                            "value": start,
                            "value-unit": "string",
                        },
                        {
                            "icon": "target",
                            "label": "Low",
                            "value": low,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "warning",
                            "label": "Medium",
                            "value": medium,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "malware",
                            "label": "High",
                            "value": high,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "malicious",
                            "label": "Critical",
                            "value": veryhigh,
                            "value-unit": "integer",
                        },     
                                        
                    ],
                    "cache_scope": "org",
                }
            )
    else:
        return jsonify_data(
            {
                
            }
        )
         

@app.route('/health', methods=['POST'])
def health():   
    data = {'status': 'ok'}
    return jsonify({'data': data})    
    
if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(port=5577,debug=True)
    