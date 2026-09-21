from __future__ import annotations
import time

# `wg show <iface> dump` emits an interface line of
#   private-key, public-key, listen-port, fwmark                (4 fields)
# and one peer line per peer of
#   public-key, preshared-key, endpoint, allowed-ips,
#   latest-handshake, transfer-rx, transfer-tx, persistent-keepalive (8 fields)
#
# `wg show all dump` prefixes every line with the interface name, giving
# 5 and 9 fields respectively. Both variants are accepted here; the
# private key is only ever used to locate the public key -- it is never
# read into the parsed result.

def parse_dump(text,names=None,required=None,now=None):
    names=names or {}; required=set(required or []); now=now or int(time.time()); interfaces=[]; current=None
    for row in text.splitlines():
        b=row.split('\t')
        if len(b) in (4,5):
            offset=1 if len(b)==5 else 0
            interface=b[0] if offset else None
            public_key=b[offset+1]
            current={"interface":interface,"public_key_short":public_key[:8],"listen_port":int(b[offset+2] or 0),"fwmark":b[offset+3],"peers":[]}
            interfaces.append(current);continue
        if current and len(b) in (8,9):
            offset=1 if len(b)==9 else 0
            key=b[offset]; hs=int(b[offset+4] or 0)
            current["peers"].append({"public_key":key,"public_key_short":key[:8],"friendly_name":names.get(key),"endpoint":b[offset+2] or None,"allowed_ips":b[offset+3].split(',') if b[offset+3] else [],"latest_handshake_seconds":now-hs if hs else None,"rx_bytes":int(b[offset+5] or 0),"tx_bytes":int(b[offset+6] or 0),"persistent_keepalive":int(b[offset+7] or 0) or None,"required":key in required})
    return interfaces
