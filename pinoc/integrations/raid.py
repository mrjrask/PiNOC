from __future__ import annotations
import re

def parse_mdstat(text):
    arrays=[]
    for block in re.split(r'\n(?=\S)',text.strip()):
        lines=block.splitlines(); m=re.match(r'(md\d+)\s*:\s*(\w+)\s+(raid\d+)\s+(.+)',lines[0]) if lines else None
        if not m:continue
        detail=' '.join(lines[1:]); counts=re.search(r'\[(\d+)/(\d+)\]\s*\[([^]]+)\]',detail); progress=re.search(r'(?:recovery|resync|reshape)\s*=\s*([\d.]+)%',detail); speed=re.search(r'speed=([^\s]+)',detail); finish=re.search(r'finish=([^\s]+)',detail)
        expected=int(counts.group(1)) if counts else None; active=int(counts.group(2)) if counts else None; failed=(expected-active) if expected is not None else 0
        arrays.append({"array":m.group(1),"state":m.group(2),"level":m.group(3),"members":m.group(4).split(),"expected_devices":expected,"active_devices":active,"failed_devices":failed,"spare_devices":sum('(S)' in x for x in m.group(4).split()),"degraded":bool(failed),"rebuild":bool(progress),"progress_percent":float(progress.group(1)) if progress else None,"estimated_completion":finish.group(1) if finish else None,"speed":speed.group(1) if speed else None})
    return arrays
