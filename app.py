"""main app"""
#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)

import os
import json
from datetime import date, timedelta
from operator import itemgetter
import urllib3
import requests
from requests.exceptions import Timeout
from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)

# from requests_toolbelt.utils import dump
import pybase64
from crayons import red, blue, green
from errors import InvalidArgumentError
from schemas import DashboardTileDataSchema
from tile_data_formats import (
    metric_tile_data_format_events,
    donut_data_risk_count,
    data_table_format_events,
    donut_data_vln_device_count,
    vuln_table_data,
    jsonify_data,
)
from tile_formats import displayed_tiles


# remove certificate warnings
urllib3.disable_warnings()

CENTER_PORT = 443
CENTER_BASE_URLV3 = "api/3.0"
CENTER_BASE_URLV1 = "api/1.0"
CENTER_API_CONSTRUCT_EVENT = "event"
CENTER_API_CONSTRUCT_RISK = "dashboard/risk-score/devices/counts"
CENTER_API_CONSTRUCT_EVENT_COUNT = "dashboard/vulnerabilities/counts"
# center_api_construct_event_cat = "dashboard/events/categories"
CENTER_API_CONSTRUCT_PRESET = "presets"

# Calculate date 30 days ago for URL queries
current_date = date.today().isoformat()
thirty_days_ago = (date.today() - timedelta(days=30)).isoformat()
#
# params_crit= {'limit': '2000', 'start': '2022-01-01','severity': 'veryhigh',
# 'severity':'high','category':'Control System Events',
# 'category':'Signature Based Detection','category':'Anomaly Detection'}
#
# params_crit = {'limit': '2000', 'start': '2022-01-01','severity':'high',
# 'severity':'veryhigh','category':'security'}
#
# params_crit = {'limit':'2000','category':'Cisco Cyber Vision Administration',
# 'category':'Security Events','category':'Anomaly Detection'}
#
#
query_string1 = {"limit": "2000", "start": thirty_days_ago}
"""# This is concatentated with the query string to provide 2 category types..."""
query_string2 = {"limit": "2000", "category": "Cisco Cyber Vision Operations"}

"""
# query_string2 = {'limit':'2000','severity':'veryhigh','category':'Security Events'}
"""
query_string3 = {"limit": "2000", "start": thirty_days_ago, "end": ""}

#  All these functions extract data via the Cyber Vision API for each dashboard
def get_events(cv_ip, cv_key):
    """Get events"""

    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": cv_key}
        r_get = requests.get(
            f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV1}/{CENTER_API_CONSTRUCT_EVENT}",
            # params=query_string1,
            headers=headers,
            verify=False,
            timeout=6,
            allow_redirects=False,
            params={
                "category": [
                    "Security Events",
                    "Cisco Cyber Vision Operations",
                    "Cisco Cyber Vision Administration",
                    "Anomaly Detection",
                    "Control Systems Events",
                ],
                **query_string1,
            },
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


def get_risk_count(cv_ip, cv_key):
    """get risk count"""
    try:
        headers = {"x-token-id": cv_key}
        r_get = requests.get(
            f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV3}/{CENTER_API_CONSTRUCT_RISK}",
            headers=headers,
            verify=False,
            allow_redirects=False,
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
            for _, vl_val in val.items():
                risk_vals.append(vl_val)
            high = risk_vals[0]
            medium = risk_vals[1]
            low = risk_vals[2]
            # total = risk_vals[3]
            # print(high, medium, low)

        return (high, medium, low)


def get_top_ten_events(cv_ip, cv_key):
    """get top ten events"""
    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": cv_key}
        r_get = requests.get(
            f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV1}/{CENTER_API_CONSTRUCT_EVENT}",
            # params=query_string1,
            headers=headers,
            verify=False,
            timeout=6,
            allow_redirects=False,
            params={
                "category": [
                    "Security Events",
                    "Cisco Cyber Vision Operations",
                    "Cisco Cyber Vision Administration",
                    "Anomaly Detection",
                    "Control Systems Events",
                ],
                **query_string1,
            },
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
    nl_list = []
    for data in raw_json_data:
        if data["severity"] in ["High", "Very High"]:
            severity = str(data["severity"])
            if len(severity) == 4:
                severity = (
                    "&nbsp;&nbsp;"
                    + severity
                    + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                )
            creation = str(data["creation_time"][:19])
            message = str(data["message"][:181])
            a_text = (
                " **&nbsp;"
                + creation
                + "**  |  **"
                + severity
                + "**  |  *"
                + message
                + "*"
            )
            nl_list.append(a_text)
            out = sorted(nl_list, key=lambda x: x[1], reverse=True)
            out.reverse()
    return out


def get_vln_device_counts(cv_ip, cv_key):
    """get vulnerabilty device counts"""
    #  Main events call for dashboard numbers for previous 30 days
    try:
        headers = {"x-token-id": cv_key}
        r_get = requests.get(
            f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV3}/{CENTER_API_CONSTRUCT_EVENT_COUNT}",
            headers=headers,
            verify=False,
            allow_redirects=False,
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
            return (0, 0, 0, 0, 0)
        for val in raw_json_data.values():
            for _, vl_val in val.items():
                vln_vals.append(vl_val)
            vtotal = vln_vals[0]
            vlow = vln_vals[1]
            vmedium = vln_vals[2]
            vhigh = vln_vals[3]
            vcritical = vln_vals[4]
                # print("in called", vhigh, vmedium, vlow, vcritical, vtotal)

            return (vhigh, vmedium, vlow, vcritical, vtotal)


def get_vuln_counts(cv_ip, cv_key):
    """get vulnerability counts"""
    # First we have to find the preset value for ALL data...
    try:
        headers = {"x-token-id": cv_key}
        r_get = requests.get(
            f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV3}/{CENTER_API_CONSTRUCT_PRESET}",
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=6,
        )

    # r_get.raise_for_status() #if there are any request errors
    except Timeout:
        print(red("we timed out on URL! - check IP address is live!" + "\n"))
    else:
        r_val = r_get.json()
        for _, data in enumerate(r_val):
            # search for 'All data' preset value
            if data["label"] == "All data":
                all_data_var = data["id"]
        # print(k)
        # print(all_data_var)
        # Once we have the all data preset ID then use it to extract all vuln
        headers = {"x-token-id": cv_key}
        url = f"https://{cv_ip}:{CENTER_PORT}/{CENTER_BASE_URLV3}/{CENTER_API_CONSTRUCT_PRESET}/{all_data_var}/visualisations/vulnerability-list"
        all_data_get = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=6)

        #  Now organise the data to vl_val pull specific values and
        # here based on CVSS of > 8.0 drop into new table as fields
        #
        r_val = all_data_get.json()
        nl_list = []
        for _, val in enumerate(r_val):
            if val["cvss"] >= 8.0:
                create_cvss_list = [
                    float(val["cvss"]),
                    # Trim the length of the date
                    str(val["publishTime"][:10]),
                    val["cve"],
                    val["title"],
                    val["countDeviceAffected"],
                ]
                nl_list.append(create_cvss_list)

        #  Order the table by CVSS value and then reverse so highest is top of list
        vuln_list = sorted(nl_list, key=itemgetter(0), reverse=True)
        return vuln_list


# def jsonify_data(data):
#     """flask jsonify data"""
#     return jsonify({"data": data})


# def jsonify_errors(data):
#     """flask jsonify error"""
#     return jsonify({"errors": [data]})


# Parse incoming headers and pull and split the token..
def pull_token():
    """use this to pull the token from the bearer"""
    scheme, jwt_token = request.headers["Authorization"].split()
    assert scheme.lower() == "bearer"
    return jwt_token


# Used to convert the token payload from base64 from pull token
def extract_cv_payload(token_in):
    """part of hack to get payload from JWT"""

    full = token_in
    extract_payload = full.split(".")
    # Bit of a hack.. the payload needs padding to get valid base64 decode length
    pad_payload = str(extract_payload[1]) + "=="
    payload_to_bytes = pybase64.b64decode(pad_payload)
    payload_string = payload_to_bytes.decode("ascii")
    payload_dict = json.loads(payload_string)

    # These 2 values we need for the call into Cyber Vision.. IP address and API Key
    cv_values = [payload_dict["CyberVision_IP"], payload_dict["CyberVision_Key"]]

    cv_ip = cv_values[0]
    cv_key = cv_values[1]
    # print(cv_ip, cv_key)
    return (cv_ip, cv_key)


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


app = Flask(__name__)
# This forces return of data to secure X in recieved dictionary order
# otherwise its alphabetical in jsonify
#
app.config["JSON_SORT_KEYS"] = False

#  EDITED OUT ROUTES FROM DEFAULT CONFIG FOR FLASK
# @app.route("/")
# def test0():
#     return "<h1>RELAY MODULE IS UP</h1>"


# @app.route("/test")
# def test():
#     truc = 2 + 40
#     return "<h1>Sounds Good the server is UP " + str(truc) + "</h1>"


@app.errorhandler(404)
def page_not_found(_):
    """404 from client side"""
    return (
        render_template(
            "error.html",
            error_title="404 Not Found",
            error_message="The requested page could not be found.",
        ),
        404,
    )


@app.errorhandler(401)
def not_found(_):
    """401 from client side"""
    return (
        render_template(
            "error.html",
            error_title="401 Unauthorised",
            error_message="Your not authorised !.",
        ),
        401,
    )


@app.errorhandler(500)
def not_found_1(_):
    """500 from client side"""
    return (
        render_template(
            "error.html",
            error_title="500 Internal Server Error",
            error_message="There was an error processing your request",
        ),
        500,
    )


@app.route("/tiles", methods=["POST"])
def tiles():
    """used to pull actual tiles - not tile data"""
    return jsonify_data(displayed_tiles())


@app.route("/tiles/tile-data", methods=["POST"])
# extract and insert data into the tile..
def tile_data():
    """use this to pull the actual tile data"""
    # Print statements used to debug incoming  requests from secureX
    # print(red("INCOMING HEADERS"))
    # print(request.headers)
    # print(request.data)
    # print(request.json)

    # This function parses the authorization header to extract the JWT token
    pulled_token = pull_token()

    # This function is used to extract and decode the embedded JWT payload from the token
    # and pulls the IP and Key from the JWT it then forwards them to each API call into Cyber Vision
    cv_payload = extract_cv_payload(pulled_token)
    cv_ip = cv_payload[0]
    cv_key = cv_payload[1]
    # print(green(pulled_token))
    #
    # This function is parsing the body of the API request from secureX to confirm
    # the tile-id it then calls each function type to display the tile contents data which
    # is in tile_data_formats.py
    #
    req = get_json(DashboardTileDataSchema())
    if req["tile_id"] == "event-count":
        start, low, medium, high, veryhigh = get_events(cv_ip, cv_key)
        # # send  data to be formatted for the tile..
        return jsonify_data(
            metric_tile_data_format_events(start, low, medium, high, veryhigh)
        )

    # elif req["tile_id"] == "risk-count":
    #     high, medium, low = get_risk_count(cv_ip, cv_key)
    #     # if high == 0 & medium == 0 & low == 0:
    #     #     high = 0
    #     #     medium = 0
    #     #     low = 0
    #     total = high + medium + low
    #     return jsonify_data(
    #         vert_bar_chart_tile_data_format_risk(high, medium, low, total)
    #     )
    if req["tile_id"] == "risk-count-donut":
        high, medium, low = get_risk_count(cv_ip, cv_key)
        # if high == 0 & medium == 0 & low == 0:
        #     high = 0
        #     medium = 0
        #     low = 0
        total = high + medium + low
        return jsonify_data(donut_data_risk_count(high, medium, low, total))

    if req["tile_id"] == "top-ten-event":
        full_list = []
        top10 = []
        full_list = get_top_ten_events(cv_ip, cv_key)
        # print(red(len(full_list)))
        # for g_val in range(len(full_list)):
        h_val = len(full_list)
        if len(full_list) < 21:
            g_val = h_val
        else:
            h_val = 21
        for g_val in range(h_val):
            top10.append(full_list[g_val])
        return jsonify_data(data_table_format_events(top10))

    if req["tile_id"] == "vln-device-count":
        vhigh, vmedium, vlow, vcritical, vtotal = get_vln_device_counts(cv_ip, cv_key)
        return jsonify_data(
            donut_data_vln_device_count(vhigh, vmedium, vlow, vcritical, vtotal)
        )

    if req["tile_id"] == "top-vulnerable":
        vuln_list = get_vuln_counts(cv_ip, cv_key)
        data_for_table = vuln_table_data(vuln_list)
        # print(json.dumps(data_for_table, indent=2))
        return jsonify_data(data_for_table)

    # Just an extra test tile to try formatting etc out
    # elif req["tile_id"] == "test-markdown":
    #     return jsonify_data(testing_example())

    # else:
    #     print ('ITS NOT')


@app.route("/health", methods=["POST"])
def health():
    """simple health of app call from secureX"""
    data = {"status": "ok"}
    return jsonify({"data": data})


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    # app.run(debug=True,host='0.0.0.0', port=4000)
    # app.run(port=5577, debug=True)
    app.run(debug=True)
