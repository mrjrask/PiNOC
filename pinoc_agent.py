#!/usr/bin/env python3
"""Unprivileged outbound PiNOC agent with a deliberately small protocol."""
from __future__ import annotations
import argparse, base64, fnmatch, json, os, platform, resource, shutil, signal, subprocess, sys, threading, time, urllib.error, urllib.request
from pathlib import Path
from pinoc.development import AGENT_VERSION,PROTOCOL_VERSION,DevelopmentGateway,SENSITIVE

def version(cmd):
    try:return subprocess.run(cmd,capture_output=True,text=True,timeout=3,env={"PATH":"/usr/local/bin:/usr/bin:/bin","LC_ALL":"C"}).stdout.strip().splitlines()[0][:100]
    except (OSError,subprocess.SubprocessError,IndexError):return None

def discover(roots=()):
    caps={name:(version([name,"--version"]) if shutil.which(name) else False) for name in ("python3","git","node","npm","docker","ffmpeg","vcgencmd")}
    caps.update({"python":caps.pop("python3"),"systemd":bool(shutil.which("systemctl")),"gpio":Path("/dev/gpiochip0").exists(),"i2c":bool(list(Path("/dev").glob("i2c-*"))),"spi":bool(list(Path("/dev").glob("spidev*"))),"camera":bool(list(Path("/dev").glob("video*"))),"display":bool(list(Path("/dev/dri").glob("card*"))),"framebuffer":Path("/dev/fb0").exists(),"x11":bool(os.getenv("DISPLAY")),"wayland":bool(os.getenv("WAYLAND_DISPLAY"))})
    model=""
    try:model=Path("/proc/device-tree/model").read_text().rstrip("\0")
    except OSError:pass
    mem=0
    try:mem=int(next(x.split()[1] for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemTotal:")))*1024
    except (OSError,ValueError,StopIteration):pass
    hardware={"model":model,"ram_bytes":mem,"architecture":platform.machine(),"kernel":platform.release(),"gpio_available":caps["gpio"],"i2c_buses":[x.name for x in Path("/dev").glob("i2c-[0-9]*")],"spi_devices":[x.name for x in Path("/dev").glob("spidev*")],"camera_devices":[x.name for x in Path("/dev").glob("video[0-9]*")],"framebuffers":[x.name for x in Path("/dev").glob("fb[0-9]*")],"drm_displays":[x.name for x in Path("/sys/class/drm").glob("card*-*")],"display_session":"wayland" if caps["wayland"] else "x11" if caps["x11"] else "none"}
    candidates=[]
    for root in roots:
        base=Path(root).resolve()
        if base.is_dir():
            for git in list(base.glob("*/.git"))+([base/".git"] if (base/".git").exists() else []):candidates.append({"path":str(git.parent.resolve()),"repository":version(["git","-C",str(git.parent),"remote","get-url","origin"])})
    return caps,hardware,candidates[:100]

class Executor:
    def __init__(self):self.processes={};self.lock=threading.Lock()
    @staticmethod
    def safe_path(root,relative,patterns=SENSITIVE,must_exist=True):
        if not isinstance(relative,str) or not relative or Path(relative).is_absolute():raise ValueError("absolute or empty path rejected")
        if any(fnmatch.fnmatch(part,p) for part in Path(relative).parts for p in patterns):raise ValueError("sensitive file denied")
        base=Path(root).resolve(strict=True);target=(base/relative).resolve(strict=must_exist)
        if target!=base and base not in target.parents:raise ValueError("workspace path escape rejected")
        if base!=Path(root).resolve(strict=True):raise ValueError("workspace root changed")
        return target
    @staticmethod
    def limits(timeout):
        resource.setrlimit(resource.RLIMIT_CPU,(timeout+2,timeout+2));resource.setrlimit(resource.RLIMIT_NOFILE,(128,128));resource.setrlimit(resource.RLIMIT_FSIZE,(20*1024*1024,20*1024*1024))
        if hasattr(resource,"RLIMIT_NPROC"):resource.setrlimit(resource.RLIMIT_NPROC,(64,64))
        if hasattr(resource,"RLIMIT_AS"):resource.setrlimit(resource.RLIMIT_AS,(1024*1024*1024,1024*1024*1024))
    def cancel(self,jid):
        with self.lock:proc=self.processes.get(jid)
        if proc and proc.poll() is None:
            try:os.killpg(proc.pid,signal.SIGTERM);time.sleep(.2);os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    def execute(self,job):
        started=time.monotonic();jid=job["job_id"];kind=job["job_type"];ws=job.get("workspace") or {};limit=int(job["output_limit_bytes"]);root=Path(ws.get("path","/")).resolve(strict=True)
        try:
            if kind=="file_read":
                target=self.safe_path(root,job["request"].get("relative_path"),ws.get("sensitive_patterns",SENSITIVE));data=target.read_bytes()
                if not target.is_file():raise ValueError("not a regular file")
                if len(data)>job["file_limit_bytes"]:raise ValueError("file exceeds read limit")
                try:text=data.decode("utf-8")
                except UnicodeDecodeError:raise ValueError("binary file denied")
                return self.done(started,0,text,"","file read")
            argv=self.argv(job,root)
            env={"PATH":"/usr/local/bin:/usr/bin:/bin","HOME":str(root),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TMPDIR":"/tmp"};env.update(job.get("environment",{}))
            proc=subprocess.Popen(argv,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=False,start_new_session=True,preexec_fn=lambda:self.limits(int(job["timeout_seconds"])))
            with self.lock:self.processes[jid]=proc
            try:out,err=proc.communicate(timeout=int(job["timeout_seconds"]));status="succeeded" if proc.returncode==0 else "failed";etype=None if proc.returncode==0 else "command_failed"
            except subprocess.TimeoutExpired:
                self.cancel(jid);out,err=proc.communicate();status="timed_out";etype="job_timeout"
            finally:
                with self.lock:self.processes.pop(jid,None)
            artifacts=self.collect(root,ws.get("artifact_patterns",[]),job["artifact_limits"])
            return self.done(started,proc.returncode,out.decode("utf-8","replace")[:limit],err.decode("utf-8","replace")[:limit],"command completed" if proc.returncode==0 else status,status,etype,len(out)>limit,len(err)>limit,artifacts)
        except Exception as exc:return self.done(started,None,"",str(exc),"job rejected","failed","invalid_request")
    def argv(self,job,root):
        kind=job["job_type"];req=job["request"]
        if kind=="capabilities":return [sys.executable,"-c","print('capabilities reported by heartbeat')"]
        if kind=="workspace_info":return ["git","status","--porcelain=v2","--branch"]
        if kind=="git_status":return ["git","status","--porcelain=v2","--branch"]
        if kind=="git_diff":
            argv=["git","diff","--no-ext-diff"]
            if req.get("staged"):argv.append("--cached")
            if req.get("relative_path"):argv.extend(["--",str(self.safe_path(root,req["relative_path"]).relative_to(root))])
            return argv
        if kind=="service_status":
            service=req.get("relative_path")
            if service not in job["workspace"].get("services",[]):raise ValueError("service is not approved")
            return ["systemctl","show",service,"--property=ActiveState,SubState,MainPID"]
        if kind=="log_read":
            service=req.get("relative_path")
            if service not in job["workspace"].get("services",[]):raise ValueError("service is not approved")
            return ["journalctl","--no-pager","-u",service,"-n",str(req.get("lines",200))]
        return job.get("argv") or {"python":["python3","-m","compileall","."],"pytest":["python3","-m","pytest"],"npm_test":["npm","test"]}.get(kind,[])
    @staticmethod
    def collect(root,patterns,limits):
        result=[];total=0
        for pattern in patterns:
            for path in root.glob(pattern):
                real=path.resolve()
                if root not in real.parents or not real.is_file():continue
                data=real.read_bytes()
                if len(result)>=limits["count"] or len(data)>limits["file_bytes"] or total+len(data)>limits["total_bytes"]:continue
                total+=len(data);result.append({"name":path.name,"data":base64.b64encode(data).decode(),"content_type":"application/octet-stream"})
        return result
    @staticmethod
    def done(started,code,out,err,summary,status="succeeded",etype=None,ot=False,et=False,artifacts=None):return {"status":status,"exit_code":code,"stdout":out,"stderr":err,"summary":summary,"error_type":etype,"stdout_truncated":ot,"stderr_truncated":et,"duration_ms":int((time.monotonic()-started)*1000),"artifacts":artifacts or [],"result":{"status":status,"exit_code":code}}

class Client:
    def __init__(self,config):self.c=config;self.executor=Executor()
    def request(self,path,data=None,signed=True):
        body=json.dumps(data or {},separators=(",",":"),sort_keys=True).encode();headers={"Content-Type":"application/json"}
        if signed:
            stamp=str(int(time.time()));nonce=os.urandom(16).hex();headers.update({"X-PiNOC-Agent":self.c["agent_id"],"X-PiNOC-Timestamp":stamp,"X-PiNOC-Nonce":nonce,"X-PiNOC-Signature":DevelopmentGateway.sign(self.c["agent_id"],self.c["credential"],stamp,nonce,body)})
        req=urllib.request.Request(self.c["server"].rstrip("/")+path,data=body,headers=headers,method="POST")
        with urllib.request.urlopen(req,timeout=30) as response:return json.load(response)
    def heartbeat(self):
        caps,hardware,candidates=discover(self.c.get("discovery_roots",[]));body={"hostname":platform.node(),"model":hardware["model"],"architecture":hardware["architecture"],"agent_version":AGENT_VERSION,"protocol_version":PROTOCOL_VERSION,"capabilities":caps,"hardware":hardware,"candidates":candidates};return self.request("/api/v1/agent/heartbeat",body)
    def run(self):
        while True:
            try:
                response=self.heartbeat()
                for jid in response.get("cancel",[]):self.executor.cancel(jid)
                job=response.get("job")
                if job:
                    self.request(f"/api/v1/agent/jobs/{job['job_id']}/result",{"status":"running"});self.request(f"/api/v1/agent/jobs/{job['job_id']}/result",self.executor.execute(job))
            except Exception as exc:print(f"pinoc-agent: {exc}",file=sys.stderr)
            time.sleep(max(2,min(60,int(self.c.get("poll_seconds",5)))))

def main():
    p=argparse.ArgumentParser();p.add_argument("--config",default="/etc/pinoc-agent/config.json");p.add_argument("--enroll",action="store_true");p.add_argument("--code");a=p.parse_args();path=Path(a.config);config=json.loads(path.read_text()) if path.exists() else {}
    if a.enroll:
        if not a.code or not config.get("server"):p.error("--code and server config are required")
        caps,hardware,_=discover(config.get("discovery_roots",[]));client=Client(config);answer=client.request("/api/v1/agent/enroll",{"enrollment_code":a.code,"hostname":platform.node(),"model":hardware["model"],"architecture":hardware["architecture"],"agent_version":AGENT_VERSION,"protocol_version":PROTOCOL_VERSION,"capabilities":caps,"hardware":hardware},False);config.update(answer);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(config,indent=2)+"\n");os.chmod(path,0o600);return 0
    for key in ("server","agent_id","credential"):
        if not config.get(key):p.error(f"missing {key} in config")
    if not config["server"].startswith("https://") and not config.get("allow_insecure_http"):p.error("HTTPS is required (set allow_insecure_http only for isolated testing)")
    Client(config).run()
if __name__=="__main__":raise SystemExit(main())
