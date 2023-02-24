"""tiles formats"""
#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)
#  This builds the data for each tile display

from typing import Any

# import markdown
# import json
from flask import jsonify


def jsonify_data(data) -> Any:
    """returns json in flask"""
    return jsonify({"data": data})


def jsonify_errors(data):
    """builtin"""
    return jsonify({"errors": [data]})


# this file includes the data used in the tile  delivered data structures
def metric_tile_data_format_events(start, low, medium, high, veryhigh):
    """returns data for metric event values"""
    return {
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
                "icon": "malicious",
                "label": "Critical",
                "value": veryhigh,
                "value-unit": "integer",
            },
            {
                "icon": "malware",
                "label": "High",
                "value": high,
                "value-unit": "integer",
            },
            {
                "icon": "warning",
                "label": "Medium",
                "value": medium,
                "value-unit": "integer",
            },
            {
                "icon": "target",
                "label": "Low",
                "value": low,
                "value-unit": "integer",
            },
        ],
        "cache_scope": "org",
    }


# def vert_bar_chart_tile_data_format_risk(high, medium, low, total):
#     """first attempt at bar charts using risk value"""
#     return {
#         "valid_time": {
#             "start_time": "2021-04-27T18:06:26.000Z",
#             "end_time": "2021-04-28T18:06:26.000Z",
#         },
#         "tile_id": "horizontal_histogram_tile",
#         "keys": [
#             {"key": "low risk", "label": "Low"},
#             {"key": "medium risk", "label": "Medium"},
#             {"key": "high risk", "label": "High"},
#             {"key": "Total", "label": "Total"},
#         ],
#         "cache_scope": "user",
#         "key_type": "string",
#         "period": "last_30_days",
#         "observed_time": {
#             "start_time": "2021-04-27T18:06:26.000Z",
#             "end_time": "2021-04-28T18:06:26.000Z",
#         },
#         "key_type": "string",
#         "color_scale": "status",
#         "data": [
#             {
#                 "values": [
#                     {
#                         "key": "low risk",
#                         "value": low,
#                         "link_uri": "https://www.cisco.com",
#                     },
#                     {
#                         "key": "medium risk",
#                         "value": medium,
#                         "link_uri": "https://www.cisco.com",
#                     },
#                     {
#                         "key": "high risk",
#                         "value": high,
#                         "link_uri": "https://www.cisco.com",
#                     },
#                 ],
#                 "label": "Risk Value by Device Count",
#                 "value": total,
#             },
#         ],
#     }


def donut_data_risk_count(high, medium, low, _):
    """returns donut data for risk values"""
    return {
        "labels": [["high", "medium", "low"]],
        "valid_time": {
            "start_time": "2021-04-28T16:48:18.000Z",
            "end_time": "2021-04-28T17:48:18.000Z",
        },
        "tile_id": "donut_tile",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": "2021-04-28T16:48:18.000Z",
            "end_time": "2021-04-28T17:48:18.000Z",
        },
        "color_scale": "status",
        "data": [
            {
                "key": 0,
                "value": high,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 10},
                ],
            },
            {
                "key": 1,
                "value": medium,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 8},
                ],
            },
            {
                "key": 2,
                "value": low,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
                ],
            },
            # {
            #     "key": 3,
            #     "value": total,
            #     "segments": [
            #         # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
            #     ],
            # },
            # {
            #     "key": 4,
            #     "value": vtotal,
            #     "segments": [
            #         # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
            #     ],
            # },
        ],
    }


def data_table_format_events(top10):
    """top 10 events data formatting"""
    return {
        "valid_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "tile_id": "markdown_tile",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "data": [event + "\n" for event in top10[:20]],
    }


def donut_data_vln_device_count(vhigh, vmedium, vlow, vcritical, _):
    """donut data for vuln count"""
    return {
        "labels": [["high", "medium", "low", "critical"]],
        "valid_time": {
            "start_time": "2021-04-28T16:48:18.000Z",
            "end_time": "2021-04-28T17:48:18.000Z",
        },
        "tile_id": "donut_tile",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": "2021-04-28T16:48:18.000Z",
            "end_time": "2021-04-28T17:48:18.000Z",
        },
        "color_scale": "status",
        "data": [
            {
                "key": 0,
                "value": vhigh,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 10},
                ],
            },
            {
                "key": 1,
                "value": vmedium,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 8},
                ],
            },
            {
                "key": 2,
                "value": vlow,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
                ],
            },
            {
                "key": 3,
                "value": vcritical,
                "segments": [
                    # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
                ],
            },
            # {
            #     "key": 4,
            #     "value": vtotal,
            #     "segments": [
            #         # {"key": 0, "link_uri": "https://www.google.com", "value": 0},
            #     ],
            # },
        ],
    }


def vuln_table_data(vuln_data):
    """vuln table data"""
    # we need to merge the dictionary keys which are also the table headings \
    #  with the returned values
    # so we have to create a dictionary entry for every line for the table..
    # these loops process the incoming lists and join the keys to create
    # a dict entry for each line..we pass this back as result set
    v_list = vuln_data
    #  list of the keys to merge to create the dict entries
    k_list = ["CVSS", "date", "CVE", "small_message", "dev_impacted", "link_uri"]
    # https://www.cve.org/CVERecord?id=CVE-2020-11896
    d_results = []
    w = 0
    # for idx in range(len(v_list) - 1):
    for idx in range(len(vuln_data) - 1):

        idx = idx + 1
        # w == 0
        d_results.append(
            {
                k_list[0]: v_list[idx][w],
                k_list[1]: v_list[idx][w + 1],
                k_list[2]: v_list[idx][w + 2],
                k_list[3]: v_list[idx][w + 3],
                k_list[4]: v_list[idx][w + 4],
                # Hot Link to CVE database for CVE
                k_list[5]: str("https://www.cve.org/CVERecord?id=")
                + str(v_list[idx][w + 2]),
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
                    "content_type": "linked_text",
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
            #    So this is a LIST containing dictionaries.
            # so you can remove the outside list brackets..
            "rows": d_results
            #
            # This is an example of the dictionary per line entry format..
            # created dynamically in the results table
            # {
            #     "CVSS": "8.9",
            #     "date": "22-10-22",
            #     "CVE": "CVW-2017-0659",
            #     "small_message": "Modicon controller bug",
            #     "dev_impacted": "2",
            # "link_uri": "HTTP HOT LINK FOR LINKED FIELD"
            # },
            # {
            #     "CVSS": "10.0",
            #     "date": "1234567",
            #     "CVE": "CVE-2020-0659",
            #     "small_message": "siemens bug",
            #     "dev_impacted": "1",
            # },
        },
    }


# This is the testing tile data.
# def testing_example():
#     """this is just a testing function"""
#     return {
#         "valid_time": {
#             "start_time": "2021-04-28T17:06:26.000Z",
#             "end_time": "2021-04-28T18:06:26.000Z",
#         },
#         "tile_id": "top-vulnerable",
#         "cache_scope": "user",
#         "period": "last_hour",
#         "observed_time": {
#             "start_time": "2021-04-28T17:06:26.000Z",
#             "end_time": "2021-04-28T18:06:26.000Z",
#         },
#         "data": [
#             "# *apples*",
#             "# ba**nan**as" + "\n",
#             "***" + "\n",
#             "hahahaha" + "\n",
#             "***",
#             "[Duck Duck Go](https://duckduckgo.com)" + "\n",
#             "I love supporting the **[EFF](https://eff.org)**",
#             "This is the *[Markdown Guide](https://www.markdownguide.org)*.See the section on [`code`](#code).",
#         ],
#     }
