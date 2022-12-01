from utils import jsonify

#this file includes the data used in the tile data structures
def metric_tile_data_format(start, low ,medium , high , veryhigh):
	return(
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
	    )


def donut_tile_data_format():
    return(
    payload_for_donut = {
    "labels": [
        [
            "Open",
            "New",
            "Closed"
        ],
        [
            "Assigned",
            "Unassigned"
        ]
    ],
    "valid_time": {
        "start_time": "2021-04-28T16:48:18.000Z",
        "end_time": "2021-04-28T17:48:18.000Z"
    },
    "tile_id": "donut_tile",
    "cache_scope": "user",
    "period": "last_hour",
    "observed_time": {
        "start_time": "2021-04-28T16:48:18.000Z",
        "end_time": "2021-04-28T17:48:18.000Z"
    },
    "data": [
        {
            "key": 0,
            "value": 2,
            "link_uri":"https://www.google.com",
            "segments": [
                {
                    "key": 0,
                    "link_uri":"https://www.google.com",
                    "value": 10
                },
                {
                    "key": 1,
                    "link_uri":"https://www.google.com",
                    "value": 20
                }
            ]
        },
        {
            "key": 1,
            "value": 10,
            "link_uri":"https://www.google.com",
            "segments": [
                {
                    "key": 0,
                    "link_uri":"https://www.google.com",
                    "value": 8
                },
                {
                    "key": 1,
                    "link_uri":"https://www.google.com",
                    "value": 0
                }
            ]
        },
        {
            "key": 2,
            "value": 5,
            "link_uri":"https://www.google.com",
            "segments": [
                {
                    "key": 0,
                    "link_uri":"https://www.google.com",
                    "value": 0
                },
                {
                    "key": 1,
                    "link_uri":"https://www.google.com",
                    "value": 0
                }
            ]
        }
    ]
})
