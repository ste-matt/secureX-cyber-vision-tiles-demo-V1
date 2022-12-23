import json
import os
import urllib3

import requests
from requests.exceptions import Timeout
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from datetime import date, datetime, timedelta
from schemas import DashboardTileDataSchema, DashboardTileSchema
from utils import get_json, get_jwt, jsonify_data
from crayons import red, green, blue, yellow, magenta, cyan

# from tile_data_formats import *
from operator import itemgetter


# remove certificate warnings
urllib3.disable_warnings()

# URL params for calls
center_token = "ics-65024d2f766a314620a7fcdeb7d95f44bb2f5ec8-aea0f5dcd40b79790dd187d38e8805d042d83392"
center_ip = "172.16.0.236"
center_port = 443
center_base_urlV3 = "api/3.0"
center_base_urlV1 = "api/1.0"
center_api_construct_event = "event"
center_api_construct_risk = "dashboard/risk-score/devices/counts"
center_api_construct_events_counts = "dashboard/vulnerabilities/counts"
center_api_construct_event_cat = "dashboard/events/categories"
center_api_construct_presets = "presets"

#     # Calculate date 30 days ago for URL queries
current_date = date.today().isoformat()
thirty_days_ago = (date.today() - timedelta(days=30)).isoformat()

# ev_high = 0
# count_c = 0

#     # Set up  various query strings for the calls
#     # params_crit = {'limit': '2000', 'start': '2022-01-01', 'severity': 'veryhigh','severity':'high','category':'Control System Events','category':'Signature Based Detection','category':'Anomaly Detection'}
#     # params_crit = {'limit': '2000', 'start': '2022-01-01','severity':'high','severity':'veryhigh','category':'security'}
#     # params_crit = {'limit':'2000','category':'Cisco Cyber Vision Administration','category':'Security Events','category':'Anomaly Detection'}
# query_string1 = {"limit": "50", "start": thirty_days_ago}
# query_string1 = {"limit": "2000"}

# #This is concatentated with the query string to provide 2 category types...
# query_string2 = {'limit':'2000','severity':'high','category':'Cisco Cyber Vision Operations'}
# query_string4 = {'limit':'2000','severity':'high'}
# query_string3 = {'limit': '2000', 'start': thirty_days_ago, 'end': ''}


def all_data():
    # First we have to find the preset value for ALL data...
    try:
        headers = {"x-token-id": center_token}
        r_get = requests.get(
            f"https://{center_ip}:{center_port}/{center_base_urlV3}/{center_api_construct_presets}",
            headers=headers,
            verify=False,
            timeout=6,
        )
    # r_get.raise_for_status() #if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        r = r_get.json()
        preset_all = ""
        for k in range(len(r)):
            # search for 'All data' preset value
            if (r[k]["label"]) == "All data":
                # print(k)
                # print(r[k]["id"])
                all_data_var = r[k]["id"]
        # Once we have the all data preset ID then use it to extract all vuln
        headers = {"x-token-id": center_token}
        all_data_get = requests.get(
            f"https://{center_ip}:{center_port}/{center_base_urlV3}/{center_api_construct_presets}/{all_data_var}/visualisations/vulnerability-list",
            # params=query_string1,
            headers=headers,
            verify=False,
            timeout=6,
        )
        #  Now organise the data to pull specific values and - here based on CVSS of > 8.0 dtop into new table as fields
        r = all_data_get.json()
        nl = []
        for d in range(len(r)):
            if r[d]["cvss"] >= 8.0:
                x = [
                    float(r[d]["cvss"]),
                    #  Trim the length of the date
                    str(r[d]["publishTime"][:10]),
                    r[d]["cve"],
                    r[d]["title"],
                    r[d]["countDeviceAffected"],
                ]
                nl.append(x)
        #  Order the table by CVSS value and then reverse so highest is top of list
        vuln_list = sorted(nl, key=itemgetter(0), reverse=True)
        return vuln_list


def vuln_table_data(vuln_data):
    # we need to merge the dictionary keys which are also the table headings , with the returned values
    # so we have to create a dictionay entry for every line for the table.. these loops process the incoming lists and join the keys to create
    # a dict entry for each line..we pass this back as result set..
    v_list = vuln_data
    #  list of the keys to merge to create the dict entries
    k_list = ["CVSS", "date", "CVE", "small_message", "dev_impacted"]
    d_results = []
    w = 0
    for idx in range(len(v_list) - 1):
        idx = idx + 1
        w == 0
        d_results.append(
            {
                k_list[0]: v_list[idx][w],
                k_list[1]: v_list[idx][w + 1],
                k_list[2]: v_list[idx][w + 2],
                k_list[3]: v_list[idx][w + 3],
                k_list[4]: v_list[idx][w + 4],
            }
        )

    return {
        "valid_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "data": {
            "columns": [
                {"key": "CVSS", "label": "Severity", "content_type": "filter_text"},
                {"key": "date", "label": "Date Discovered", "content_type": "text"},
                {
                    "key": "CVE",
                    "label": "CVE",
                    "content_type": "text",
                },
                {
                    "key": "small_message",
                    "label": "About",
                    "content_type": "text",
                },
                {
                    "key": "dev_impacted",
                    "label": "Devices Impacted",
                    "content_type": "text",
                },
            ],
            "rows": [
                d_results
                #
                # This is an example of the dictionary per line entry format.. created dynamically in the results table
                # {
                #     "CVSS": "8.9",
                #     "date": "22-10-22",
                #     "CVE": "CVW-2017-0659",
                #     "small_message": "Modicon controller bug",
                #     "dev_impacted": "2",
                # },
                # {
                #     "CVSS": "10.0",
                #     "date": "1234567",
                #     "CVE": "CVE-2020-0659",
                #     "small_message": "siemens bug",
                #     "dev_impacted": "1",
                # },
            ],
        },
    }


X = all_data()
D = vuln_table_data(X)
print("D equals :", type(D))

# print(json.dumps(D, indent=2))
