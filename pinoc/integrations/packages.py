from __future__ import annotations

def parse_apt(text,reboot_required=False,metadata_refresh=None):
    rows=[x for x in text.splitlines() if x.startswith('Inst ')]
    security=sum('security' in x.lower() for x in rows)
    return {"updates_available":len(rows),"security_updates":security,"reboot_required":bool(reboot_required),"last_metadata_refresh":metadata_refresh}
