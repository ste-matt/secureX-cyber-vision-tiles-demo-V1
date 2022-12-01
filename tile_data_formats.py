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


def donut_tile_data_format(high, medium, low, total):
    return({
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

def hz_bar_chart_tile_data_format(high, medium, low, total):
    return(
        {
    "valid_time": {
        "start_time": "2021-04-27T18:06:26.000Z",
        "end_time": "2021-04-28T18:06:26.000Z"
    },
    "tile_id": "horizontal_histogram_tile",
    "keys": [
        {
            "key": "somethingpat",
            "label": "something label"
        }
    ],
    "cache_scope": "user",
    "key_type": "string",
    "period": "last_30_days",
    "observed_time": {
        "start_time": "2021-04-27T18:06:26.000Z",
        "end_time": "2021-04-28T18:06:26.000Z"
    },
    "data": [
        {
            "key": "1620597601000",
            "label": "19:00:00",
            "value": high,
            "values": [
                {
                    "key": "somethingpat",
                    "value": high,
                    "tooltip": "something: 30",
                    "link_uri": "https://www.google.com"
                }
            ]
        },     
        {
            "key": "1620511201000",
            "label": "19:00:00",
            "value": medium,
            "values": [
                {
                    "key": "somethingpat",
                    "value": medium,
                    "tooltip": "something: 10",
                    "link_uri": "https://www.google.com"
                }
            ]
        },    
        {
            "key": "1620624801000",
            "label": "19:00:00",
            "value": low,
            "values": [
                {
                    "key": "somethingpat",
                    "value": low,
                    "tooltip": "something: 10",
                    "link_uri": "https://www.google.com"
                }
            ]
        },
        {
            "key": "1620433333000",
            "label": "19:00:00",
            "value": total,
            "values": [
                {
                    "key": "somethingpat",
                    "value": total,
                    "tooltip": "something: 20",
                    "link_uri": "https://www.google.com"
                }
            ]
        }
    ]
})