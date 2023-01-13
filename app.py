#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)

from config import center_ip, center_port, center_token
import os
import urllib3
import json
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
from utils import get_json, get_jwt, jsonify_data, extract_CV_payload
from crayons import red, green, blue, yellow, magenta, cyan
from tile_data_formats import *
from tile_formats import *
from operator import itemgetter
from requests_toolbelt.utils import dump


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

# Calculate date 30 days ago for URL queries
current_date = date.today().isoformat()
thirty_days_ago = (date.today() - timedelta(days=30)).isoformat()

# Set up  various query strings for the calls
# params_crit = {'limit': '2000', 'start': '2022-01-01', 'severity': 'veryhigh','severity':'high','category':'Control System Events','category':'Signature Based Detection','category':'Anomaly Detection'}
# params_crit = {'limit': '2000', 'start': '2022-01-01','severity':'high','severity':'veryhigh','category':'security'}
# params_crit = {'limit':'2000','category':'Cisco Cyber Vision Administration','category':'Security Events','category':'Anomaly Detection'}
query_string1 = {"limit": "2000", "start": thirty_days_ago}
# This is concatentated with the query string to provide 2 category types...
query_string2 = {"limit": "2000", "category": "Cisco Cyber Vision Operations"}
# query_string2 = {'limit':'2000','severity':'veryhigh','category':'Security Events'}
query_string3 = {"limit": "2000", "start": thirty_days_ago, "end": ""}

#  Main events call for dashboard numbers for previous 30 days
def get_events(CV_IP, CV_Key):

    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": CV_Key}
        r_get = requests.get(
            f"https://{CV_IP}:{center_port}/{center_base_urlV1}/{center_api_construct_event}?category=Security%20Events&category=Cisco%20Cyber%20Vision%20Operations&category=Cisco%20Cyber%20Vision%20Administration",
            params=query_string1,
            headers=headers,
            verify=False,
            timeout=6,
        )
    # r_get.raise_for_status() #if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        raw_json_data = r_get.json()
        # print(type(raw_json_data))
        # print(json.dumps(raw_json_data,indent = 2))
        # Extract events totals and calculate and apply 30 day window
        ev_start = query_string1["start"]
        ev_low = len(
            [val for data in raw_json_data for val in data.values() if val == "Low"]
        )
        ev_medium = len(
            [val for data in raw_json_data for val in data.values() if val == "Medium"]
        )
        ev_high = len(
            [val for data in raw_json_data for val in data.values() if val == "High"]
        )
        ev_veryhigh = len(
            [
                val
                for data in raw_json_data
                for val in data.values()
                if val == "Very High"
            ]
        )

    return (ev_start, ev_low, ev_medium, ev_high, ev_veryhigh)


def get_risk_count(CV_IP,CV_Key):
    try:
        headers = {"x-token-id": CV_Key}
        r_get = requests.get(
            f"https://{CV_IP}:{center_port}/{center_base_urlV3}/{center_api_construct_risk}",
            headers=headers,
            verify=False,
            timeout=6,
        )
        r_get.raise_for_status()  # if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        raw_json_data = r_get.json()
        # print(type(raw_json_data))
        # print(json.dumps(raw_json_data, indent=2))
        risk_vals = []
        # high = 0
        # medium = 0
        # low = 0
        # total = 0
        # if raw_json_data == "":
        #     print(type(raw_json_data))
        #     return (0, 0, 0, 0)
        # else:
        for val in raw_json_data.values():
            for key, vl in val.items():
                risk_vals.append(vl)
            high = risk_vals[0]
            medium = risk_vals[1]
            low = risk_vals[2]
            # total = risk_vals[3]
            # print(high, medium, low)

        return (high, medium, low)


def get_top_ten_events(CV_IP, CV_Key):
    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": CV_Key}
        r_get = requests.get(
            f"https://{CV_IP}:{center_port}/{center_base_urlV1}/{center_api_construct_event}?category=Security%20Events&category=Cisco%20Cyber%20Vision%20Operations&category=Cisco%20Cyber%20Vision%20Administration",
            params=query_string1,
            headers=headers,
            verify=False,
            timeout=6,
        )
    # r_get.raise_for_status() #if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        raw_json_data = r_get.json()
        # print(type(raw_json_data))
        # print(type(raw_json_data))
        # print(json.dumps(raw_json_data, indent=2))

        # Find and print the top 10 high and very high  events.

        for data in raw_json_data:
            for keys, values in data.items():
                nl = []
                for x in range(len(raw_json_data)):
                    if (
                        raw_json_data[x]["severity"] == "High"
                        or raw_json_data[x]["severity"] == "Very High"
                    ):

                        severity = str(raw_json_data[x]["severity"])
                        f = len(severity)
                        if f == 4:
                            severity = (
                                "&nbsp;&nbsp;"
                                + severity
                                + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                            )
                        creation = str(raw_json_data[x]["creation_time"][:19])

                        message = str(raw_json_data[x]["message"][:181])
                        a = (
                            " "
                            + " **"
                            + "&nbsp;"
                            + creation
                            + "**"
                            + "  |  "
                            + "**"
                            + severity
                            + "**"
                            + " "
                            + "  |  "
                            + "*"
                            + message
                            + "*"
                        )
                        nl.append(a)
                        out = sorted(nl, key=itemgetter(1), reverse=True)
                        # print(green(out))
                        nl.reverse()

                return nl


def get_vln_device_counts(CV_IP,CV_Key):
    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": CV_Key}
        r_get = requests.get(
            f"https://{CV_IP}:{center_port}/{center_base_urlV3}/{center_api_construct_events_counts}",
            headers=headers,
            verify=False,
            timeout=6,
        )
        # USE TO DUMP FULL HTTP EXCHANGE TO CLIENT>> TOOLBELT IMPORT...
        # print(green("OUTGOING TO CV V_COUNT"))
        # dumpdata = dump.dump_all(r_get)
        # print(dumpdata.decode("utf-8"))
    # r_get.raise_for_status() #if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        raw_json_data = r_get.json()
        # print(json.dumps(raw_json_data, indent=2))
        vln_vals = []
        if raw_json_data == "":
            print(type(raw_json_data))
            return (0, 0, 0, 0)
        else:
            for val in raw_json_data.values():
                for key, vl in val.items():
                    vln_vals.append(vl)
                vtotal = vln_vals[0]
                vlow = vln_vals[1]
                vmedium = vln_vals[2]
                vhigh = vln_vals[3]
                vcritical = vln_vals[4]
                # print("in called", vhigh, vmedium, vlow, vcritical, vtotal)

                return (vhigh, vmedium, vlow, vcritical, vtotal)


def get_vuln_counts(CV_IP, CV_Key):
    # First we have to find the preset value for ALL data...
    try:
        headers = {"x-token-id": CV_Key}
        r_get = requests.get(
            f"https://{CV_IP}:{center_port}/{center_base_urlV3}/{center_api_construct_presets}",
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


def jsonify_data(data):
    return jsonify({"data": data})


def jsonify_errors(data):
    return jsonify({"errors": [data]})


def pull_token():
    scheme, pull_token = request.headers["Authorization"].split()
    assert scheme.lower() == "bearer"
    return pull_token


app = Flask(__name__)
# This forces return of data to secure X in recieved dictionary order.. otherwise its alphabetical in jsonify
app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def test0():
    return "<h1>RELAY MODULE IS UP</h1>"


@app.route("/test")
def test():
    truc = 2 + 40
    return "<h1>Sounds Good the server is UP " + str(truc) + "</h1>"


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html"), 404


@app.errorhandler(401)
def not_found(error):
    return render_template("error.html"), 401


@app.errorhandler(500)
def not_found(error):
    return render_template("error.html"), 500


@app.route("/tiles", methods=["POST"])
def tiles():
    return jsonify_data(displayed_tiles())


@app.route("/tiles/tile-data", methods=["POST"])
# extract and insert data into the tile..
def tile_data():
    # print(red("INCOMING HEADERS"))
    # print(request.headers)
    # print(request.data)
    # print(request.json)
    # set a default token to forward..
    # auth = center_token
    # use the pulled token from incoming request from secure call and compare with existing
    pulled_token = pull_token()
    CVpayload = extract_CV_payload(pulled_token)
    CV_IP = CVpayload[0]
    CV_Key = CVpayload[1]
    # print(green(pulled_token))
    # if auth == pulled_token:

    req = get_json(DashboardTileDataSchema())
    # removed the validation part - here just hard code the tile to push data to based on tile data
    # data = {'tile_id':'event-count'}
    if req["tile_id"] == "event-count":
        start, low, medium, high, veryhigh = get_events(CV_IP, CV_Key)
        # # send  data to be formatted for the tile..
        return jsonify_data(
            metric_tile_data_format_events(start, low, medium, high, veryhigh)
        )

    elif req["tile_id"] == "risk-count":
        high, medium, low = get_risk_count(CV_IP,CV_Key)
        if high == 0 & medium == 0 & low == 0:
            high = 0
            medium = 0
            low = 0
        total = high + medium + low
        return jsonify_data(
            vert_bar_chart_tile_data_format_risk(high, medium, low, total)
        )

    elif req["tile_id"] == "top-ten-event":
        full_list = []
        top10 = []
        full_list = get_top_ten_events(CV_IP, CV_Key)
        # print(red(len(full_list)))
        # for g in range(len(full_list)):
        for g in range(21):
            top10.append(full_list[g])
        # print(f"this is top 10 in calling app", top10)
        return jsonify_data(data_table_format_events(top10))

    elif req["tile_id"] == "vln-device-count":
        vhigh, vmedium, vlow, vcritical, vtotal = get_vln_device_counts(CV_IP,CV_Key)
        return jsonify_data(
            donut_data_vln_device_count(vhigh, vmedium, vlow, vcritical, vtotal)
        )

    elif req["tile_id"] == "top-vulnerable":
        vuln_list = get_vuln_counts(CV_IP, CV_Key)
        data_for_table = vuln_table_data(vuln_list)
        # print(json.dumps(data_for_table, indent=2))
        return jsonify_data(data_for_table)

    elif req["tile_id"] == "test-markdown":
        return jsonify_data(TESTING())

    # else:
    #     print ('ITS NOT')


@app.route("/health", methods=["POST"])
def health():
    data = {"status": "ok"}
    return jsonify({"data": data})


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(port=5577, debug=True)