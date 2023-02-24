"""tiles module"""
#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)
#
# includes th actual format of the used tiles.. not the enclosed data


from typing import Any

def displayed_tiles() -> list[dict[str,Any]]:
    '''this function returns the actual tiles'''

    return [
        {
            "id": "event-count",
            "type": "metric_group",
            "title": "Events by Category - last 30 days - limited to 2000",
            "periods": ["last_30_days"],
            "short_description": "Cyber Vision Event Counts",
            "description": "Cyber Vision Events for the last 30 days"
             " - similar to the Events Dashboard",
            "tags": ["Cyber Vision"],
        },
        # {
        #     "title": "Risk Count",
        #     "description": "Cyber Vision Risk numbers",
        #     "periods": ["last_30_days"],
        #     "tags": ["Cyber Vision"],
        #     "type": "horizontal_bar_chart",
        #     "short_description": "Cyber Vision Risks",
        #     "id": "risk-count",
        # },
        {
            "title": "Devices by Risk Count",
            "description": "Devices by Risk Score Donut",
            "periods": ["last_30_days"],
            "tags": ["Cyber Vision"],
            "type": "donut_graph",
            "short_description": "Cyber Vision Risk Count Donut",
            "id": "risk-count-donut",
        },
        {
            "id": "top-ten-event",
            "type": "markdown",
            "title": "Top Twenty Events By Most Recent",
            "periods": ["last_30_days"],
            "short_description": "Cyber Vision High and Very High Events",
            "description": "Last 20 High and Very High Events",
            "tags": ["Cyber Vision"],
        },
        {
            "description": "Cyber Vision Vulnerable Device Count Per Category",
            "periods": ["last_30_days"],
            "tags": ["Cyber Vision"],
            "type": "donut_graph",
            "short_description": "Cyber Vision Vulnerable Device Count",
            "title": "Vulnerable Devices Count per Category",
            "id": "vln-device-count",
        },
        {
            "id": "top-vulnerable",
            "description": "Top Vulnerabilities by Severity",
            "periods": ["last_30_days"],
            "tags": ["Cyber Vision"],
            "type": "data_table",
            "short_description": "Cyber Vision Vulnerabilities",
            "title": "Top Vulnerabilities Filter by Severity",
        },
        # {
        #     "id": "test-markdown",
        #     "type": "markdown",
        #     "title": "TESTING MARKDOWN TILE",
        #     "periods": ["last_30_days"],
        #     "short_description": "TESTING MARKDOWN TILE",
        #     "description": "TESTING MARKDOWN TILE",
        #     "tags": ["Cyber Vision"],
        # },
    ]
