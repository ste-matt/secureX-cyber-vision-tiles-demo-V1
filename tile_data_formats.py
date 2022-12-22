#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)
#
from utils import jsonify
import markdown

# this file includes the data used in the tile  delivered data structures
def metric_tile_data_format_events(start, low, medium, high, veryhigh):
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


def vert_bar_chart_tile_data_format_risk(high, medium, low, total):
    return {
        "valid_time": {
            "start_time": "2021-04-27T18:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "tile_id": "horizontal_histogram_tile",
        "keys": [
            {"key": "low risk", "label": "Low"},
            {"key": "medium risk", "label": "Medium"},
            {"key": "high risk", "label": "High"},
            {"key": "Total", "label": "Total"},
        ],
        "cache_scope": "user",
        "key_type": "string",
        "period": "last_30_days",
        "observed_time": {
            "start_time": "2021-04-27T18:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "key_type": "string",
        "color_scale": "status",
        "data": [
            {
                "values": [
                    {
                        "key": "low risk",
                        "value": low,
                        "link_uri": "https://www.cisco.com",
                    },
                    {
                        "key": "medium risk",
                        "value": medium,
                        "link_uri": "https://www.cisco.com",
                    },
                    {
                        "key": "high risk",
                        "value": high,
                        "link_uri": "https://www.cisco.com",
                    },
                ],
                "label": "Risk Value by Device Count",
                "value": total,
            },
        ],
    }


def data_table_format_events(top10):
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
        "data": [
            top10[0] + "\n",
            top10[1] + "\n",
            top10[2] + "\n",
            top10[3] + "\n",
            top10[4] + "\n",
            top10[5] + "\n",
            top10[6] + "\n",
            top10[7] + "\n",
            top10[8] + "\n",
            top10[9] + "\n",
            top10[10] + "\n",
            top10[11] + "\n",
            top10[12] + "\n",
            top10[13] + "\n",
            top10[14] + "\n",
            top10[15] + "\n",
            top10[16] + "\n",
            top10[17] + "\n",
            top10[18] + "\n",
            top10[19] + "\n",
            top10[20] + "\n",
        ],
    }


def donut_data_vln_device_count(vhigh, vmedium, vlow, vcritical, vtotal):

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


def vuln_table_data(vuln_list):
    v_list = vuln_list
    # for s in range(len(v_list)):
    #     pass
    #     print(v_list[s])
    print("Total Vuln count above 8.0 rating = ", (len(v_list)))
    row_count = len(v_list)
    print(row_count)
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
                {
                    "CVSS": "8.9",
                    "date": "22-10-22",
                    "CVE": "CVW-2017-0659",
                    "small_message": "Modicon controller bug",
                    "dev_impacted": "2",
                },
                {
                    "CVSS": "10.0",
                    "date": "1234567",
                    "CVE": "CVE-2020-0659",
                    "small_message": "siemens bug",
                    "dev_impacted": "1",
                },
            ],
        },
    }


def TESTING():
    return {
        "valid_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "tile_id": "top-vulnerable",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": "2021-04-28T17:06:26.000Z",
            "end_time": "2021-04-28T18:06:26.000Z",
        },
        "data": [
            "# *apples*",
            "# ba**nan**as" + "\n",
            "***" + "\n",
            "hahahaha" + "\n",
            "***",
            "[Duck Duck Go](https://duckduckgo.com)" + "\n",
            "I love supporting the **[EFF](https://eff.org)**",
            "This is the *[Markdown Guide](https://www.markdownguide.org)*.See the section on [`code`](#code).",
        ],
    }
