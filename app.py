import json
import os

import requests
from crayons import *
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session)

from schemas import DashboardTileDataSchema, DashboardTileSchema
from utils import get_json, get_jwt, jsonify_data
from crayons import red,green,blue,yellow,magenta,cyan

auth_token = "ics-becf2ba10ba7058ffb9651d69df46e8131090c22-d96b3d752a2899c4c4a0895076e944df49005ccb"

headers = {"Content-Type": "application/json; charset=utf-8", "x-token-id": auth_token
           }

events=[]

def cv140_ec():
    #response=requests.get('https://tod.myddns.me/api/3.0/homepage/dashboard', headers=headers , verify=False)
    response=requests.get('https://tod.myddns.me/api/3.0/dashboard/events/severities', headers=headers , verify=False)
    #response=requests.get('https://172.16.0.140/api/3.0/homepage/dashboard', headers=headers , verify=False)

    payload=response.content
    json_payload=json.loads(payload)
    # values_x = {}
    # values_y = {}
    # values_x =json_payload['event']
    
    # values_y = values_x['total']

    # for v in values_y.values():
    #     events.append(v)

    # total = events[0]
    # low = events[1]
    # medium = events[2]      
    # high = events [3]
    # critical = events[4]
    # print(total,low,medium,high,critical)    
    # return(json_payload['total'],['low'],['medium'],['high'],['critical)'])
    return (json_payload['centers'][0]['total'],json_payload['centers'][0]['low'],json_payload['centers'][0]['medium'],json_payload['centers'][0]['high'],json_payload['centers'][0]['critical'])

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
                "id": "test-summary",
                "type": "metric_group",
                "title": "Cyber Vision Events by Category",
                "periods": ["last_30_days"],
                "short_description": "CV Events",
                "description": "A longer description",
                "tags": ["test"],
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
        data = {'tile_id':'test-summary'}
        # print (green(data["tile_id"],bold=True))     
        if data["tile_id"] == "test-summary":
        #    total , low, medium, high, critical = cv140_ec()
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
                            "icon": "brain",
                            "label": "Total",
                            "value": 10,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "percent",
                            "label": "Low",
                            "value": 11,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "percent",
                            "label": "Medium",
                            "value": 12,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "percent",
                            "label": "High",
                            "value": 13,
                            "value-unit": "integer",
                        },
                        {
                            "icon": "percent",
                            "label": "Critical",
                            "value": 14,
                            "value-unit": "integer",
                        },     
                                        
                    ],
                    "cache_scope": "org",
                }
            )
    # else:
    #     return jsonify_data(
    #         {
    #             "observed_time": {
    #                 "start_time": "2020-12-28T04:33:00.000Z",
    #                 "end_time": "2021-01-27T04:33:00.000Z",
    #             },
    #             "valid_time": {
    #                 "start_time": "2021-01-27T04:33:00.000Z",
    #                 "end_time": "2021-01-27T04:38:00.000Z",
    #             },
    #             "key_type": "timestamp",
    #             "data": [
    #                 {"key": 1611731572, "value": 13},
    #                 {"key": 1611645172, "value": 20},
    #                 {"key": 1611558772, "value": 5},
    #                 {"key": 1611431572, "value": 13},
    #                 {"key": 1611345172, "value": 20},
    #                 {"key": 1611258772, "value": 5},
    #                 {"key": 1611131572, "value": 13},
    #                 {"key": 1611045172, "value": 20},
    #                 {"key": 1610958772, "value": 5},
    #                 {"key": 1610831572, "value": 13},
    #                 {"key": 1610745172, "value": 20},
    #                 {"key": 1610658772, "value": 5},
    #                 {"key": 1610531572, "value": 13},
    #                 {"key": 1610445172, "value": 20},
    #                 {"key": 1610358772, "value": 5},
    #             ],
    #             "cache_scope": "org",
    #         }
    #     )
         

@app.route('/health', methods=['POST'])
def health():   
    data = {'status': 'ok'}
    return jsonify({'data': data})    
    
if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(port=5577,debug=True)
    