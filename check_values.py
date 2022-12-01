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

ev_high = 0
count_c = 0
    
    # Set up  various query strings for the calls
    # params_crit = {'limit': '2000', 'start': '2022-01-01', 'severity': 'veryhigh','severity':'high','category':'Control System Events','category':'Signature Based Detection','category':'Anomaly Detection'}
    # params_crit = {'limit': '2000', 'start': '2022-01-01','severity':'high','severity':'veryhigh','category':'security'}
    # params_crit = {'limit':'2000','category':'Cisco Cyber Vision Administration','category':'Security Events','category':'Anomaly Detection'}
query_string1 = {'limit':'2000','start':thirty_days_ago}
#This is concatentated with the query string to provide 2 category types... 
query_string2 = {'limit':'2000','severity':'high','category':'Cisco Cyber Vision Operations'}
query_string4 = {'limit':'2000','severity':'high'}
query_string3 = {'limit': '2000', 'start': thirty_days_ago, 'end': ''}

    #  Main events call for dashboard numbers for previous 30 days
try:
    headers = { "x-token-id": center_token }
    r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_urlV1}/{center_api_construct_event}?category=Security%20Events",params=query_string2,headers=headers,verify=False, timeout = 6)
    # r_get.raise_for_status() #if there are any request errors
except Timeout:
    print (red('we timed out on URL! - check IP address is live!'+'\n'))
else:
    raw_json_data = r_get.json()
    print(type(raw_json_data))
    print(json.dumps(raw_json_data,indent = 2))



            # Extract events totals and calculate and apply 30 day window
            # ev_start = (query_string1['start'])
            # ev_low = (len([val for data in  raw_json_data for val in data.values() if val == 'Low']))
            # ev_medium = (len([val for data in raw_json_data for val in data.values() if val == 'Medium']))
    ev_high = (len([val for data in raw_json_data for val in data.values() if val == 'High']))
    count_c  =(len([val for data in raw_json_data for key,val in data.items() if val == 'Security Events']))
            

            # ev_veryhigh = (len([val for data in raw_json_data for val in data.values() if val == 'Very High']))

print(ev_high, count_c)
