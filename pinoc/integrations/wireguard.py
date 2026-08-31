from __future__ import annotations
import time

def parse_dump(text,names=None,required=None,now=None):
    names=names or {}; required=set(required or []); now=now or int(time.time()); interfaces=[]; current=None
    for row in text.splitlines():
        b=row.split('\t');
        if len(b)==5:
            current={"interface":b[0],"public_key_short":b[1][:8],"listen_port":int(b[3] or 0),"fwmark":b[4],"peers":[]};interfaces.append(current);continue
        if current and len(b)>=8:
            key=b[0]; hs=int(b[4] or 0); current["peers"].append({"public_key":key,"public_key_short":key[:8],"friendly_name":names.get(key),"endpoint":b[2] or None,"allowed_ips":b[3].split(',') if b[3] else [],"latest_handshake_seconds":now-hs if hs else None,"rx_bytes":int(b[5] or 0),"tx_bytes":int(b[6] or 0),"persistent_keepalive":int(b[7] or 0) or None,"required":key in required})
    return interfaces
