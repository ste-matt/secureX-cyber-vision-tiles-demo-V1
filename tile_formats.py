#!/usr/bin/python3
# Cisco Cyber Vision V4.x
# Version 1.0 - 2022-11-24 - Steve Matthews (stmatthe@cisco.com)
#
# includes th actualformat of the used tiles.. not the enclosed data


def displayed_tiles():
    return [
        {
            "id": "event-count",
            "type": "metric_group",
            "title": "Cyber Vision Events by Category - last 30 days",
            "periods": ["last_30_days"],
            "short_description": "Cyber Vision Event Counts",
            "description": "Cyber Vision Events for the last 30 days - similar to the Events Dashboard",
            "tags": ["Cyber Vision"],
        },
        {
            "title": "Cyber Vision Risk by Device",
            "description": "Cyber Vision Risk numbers",
            "periods": ["last_30_days"],
            "tags": ["Cyber Vision"],
            "type": "horizontal_bar_chart",
            "short_description": "Cyber Vision Risks",
            "id": "risk-count",
        },
        {
            "id": "top-ten-event",
            "type": "markdown",
            "title": "Cyber Vision Top Twenty Events",
            "periods": ["last_30_days"],
            "short_description": "Cyber Vision High and Very High Events",
            "description": "Cyber Vision Last 20 High and Very High Events",
            "tags": ["Cyber Vision"],
        },
        {
            "description": "Cyber Vision Vulnerable Device Count Per Category",
            "periods": ["last_30_days"],
            "tags": ["Cyber Vision"],
            "type": "donut_graph",
            "short_description": "Cyber Vision Vulnerable Device Count",
            "title": "Cyber Vision Vulnerable Devices Count per Category",
            "id": "vln-device-count",
        },
        {
            "id": "test-markdown",
            "type": "markdown",
            "title": "TESTING MARKDOWN TILE",
            "periods": ["last_30_days"],
            "short_description": "TESTING MARKDOWN TILE",
            "description": "TESTING MARKDOWN TILE",
            "tags": ["Cyber Vision"],
        },
    ]
