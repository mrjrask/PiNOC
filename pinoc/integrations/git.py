from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit

def _safe_remote_url(value):
    if not value:return value
    parsed=urlsplit(value)
    if parsed.scheme and parsed.netloc and "@" in parsed.netloc:
        return urlunsplit((parsed.scheme,parsed.netloc.rsplit("@",1)[1],parsed.path,parsed.query,parsed.fragment))
    return value

def normalize(name,path,output):
    lines=output.splitlines(); values={}
    for line in lines:
        if '=' in line:
            k,v=line.split('=',1);values[k]=v
    ahead=behind=None
    try:ahead,behind=map(int,values.get('ahead_behind','').split())
    except ValueError:pass
    return {"name":name,"path":path,"branch":values.get("branch"),"commit":values.get("commit"),"short_commit":values.get("commit",'')[:7] or None,"dirty":values.get("dirty") not in ('','0',None),"remote_url":_safe_remote_url(values.get("remote")),"ahead":ahead,"behind":behind,"last_commit_date":values.get("last_commit_date"),"fetch_error":values.get("fetch_error")}
