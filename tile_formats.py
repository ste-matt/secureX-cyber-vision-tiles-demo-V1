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
            "type": "vertical_bar_chart",
            "short_description": "Cyber Vision Risks",
            "id": "risk-count",
        },
        {
            "id": "top-ten-event",
            "type": "markdown",
            "title": "Cyber Vision Top Ten High and Very High Events",
            "periods": ["last_30_days"],
            "short_description": "Cyber Vision Top Ten Events - Critical and Very High",
            "description": "Cyber Vision Top Ten Events",
            "tags": ["Cyber Vision"],
        },
    ]
