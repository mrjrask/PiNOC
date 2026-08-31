from pinoc.integrations.http_apps import normalize_http
def parse_status(payload,status=None,latency_ms=None):
    x=normalize_http(payload,status,latency_ms); clients=x.get('clients',[]);x['client_count']=x.get('client_count',len(clients) if isinstance(clients,list) else None);return x
