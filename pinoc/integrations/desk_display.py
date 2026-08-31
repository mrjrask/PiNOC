from pinoc.integrations.http_apps import normalize_http

def parse_status(payload,status=None,latency_ms=None):
    x=normalize_http(payload,status,latency_ms); aliases={'profile':'current_display_profile','screen':'current_screen','last_refresh':'last_successful_data_refresh'}
    for old,new in aliases.items():
        if old in x and new not in x:x[new]=x[old]
    return x
