"""Authentication, authorization, API tokens, CSRF, and secret redaction."""
from __future__ import annotations
import copy, hashlib, hmac, json, re, secrets, threading, time
from datetime import timedelta
from functools import wraps
from typing import Any, Iterable
from flask import abort, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from pinoc.database import utcnow

ROLES={"viewer":0,"operator":1,"administrator":2}
PERMISSIONS={"view":"viewer","history.read":"viewer","alerts.read":"viewer","alerts.write":"operator","actions.execute":"operator","maintenance.write":"operator","device.power":"administrator","config.write":"administrator","users.write":"administrator"}
SECRET_KEYS=re.compile(r"password|passwd|secret|token|private.?key|credential|authorization|cookie",re.I)

def redact(value:Any)->Any:
    if isinstance(value,dict): return {str(k):("[REDACTED]" if SECRET_KEYS.search(str(k)) else redact(v)) for k,v in value.items()}
    if isinstance(value,(list,tuple)): return [redact(x) for x in value]
    text=str(value) if isinstance(value,Exception) else value
    if isinstance(text,str):
        text=re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~-]+",r"\1[REDACTED]",text)
        text=re.sub(r"(?i)((?:password|secret|token)=)[^\s&]+",r"\1[REDACTED]",text)
    return text

def restore_redacted(value:Any,current:Any,secret:bool=False)->Any:
    """Replace redaction sentinels for secret fields with their current values."""
    if secret and value=="[REDACTED]":
        if current is None:raise ValueError("redacted secret has no existing value")
        return copy.deepcopy(current)
    if isinstance(value,dict):
        existing=current if isinstance(current,dict) else {}
        return {key:restore_redacted(item,existing.get(key),bool(SECRET_KEYS.search(str(key)))) for key,item in value.items()}
    if isinstance(value,list):
        existing=current if isinstance(current,list) else []
        return [restore_redacted(item,existing[index] if index<len(existing) else None,secret) for index,item in enumerate(value)]
    return value

def hash_token(secret:str)->str:return hashlib.sha256(secret.encode()).hexdigest()

class SecurityManager:
    def __init__(self,db,enabled=False):
        self.db=db;self.enabled=bool(enabled);self.failures={};self.lock=threading.Lock()
    def create_user(self,username,password,role="viewer"):
        username=username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}",username) or role not in ROLES or len(password)<10: raise ValueError("invalid username, role, or password (minimum 10 characters)")
        self.db.execute("INSERT INTO users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)",(username,generate_password_hash(password),role,1,utcnow()))
    def authenticate(self,username,password,ip):
        now=time.monotonic()
        with self.lock:
            attempts=[x for x in self.failures.get(ip,[]) if now-x<300];self.failures[ip]=attempts
            if len(attempts)>=5:return None,"Too many login attempts; try again later."
        rows=self.db.rows("SELECT * FROM users WHERE username=? AND enabled=1",(username,)); row=rows[0] if rows else None
        valid=bool(row and check_password_hash(row["password_hash"],password))
        if not valid:
            # Perform equivalent hash work and return one generic message.
            if not row: check_password_hash(generate_password_hash("not-the-password"),password)
            with self.lock:self.failures.setdefault(ip,[]).append(now)
            return None,"Invalid username or password."
        with self.lock:self.failures.pop(ip,None)
        self.db.execute("UPDATE users SET last_login=? WHERE username=?",(utcnow(),username));return row,None
    def create_token(self,owner,scopes:Iterable[str]):
        allowed={"read:fleet","read:history","read:alerts","write:alerts","execute:safe_actions","admin:config"}; scopes=sorted(set(scopes))
        if not scopes or not set(scopes)<=allowed:raise ValueError("invalid token scopes")
        token_id=secrets.token_urlsafe(9); secret=secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO api_tokens VALUES(?,?,?,?,?,?,?)",(token_id,hash_token(secret),owner,json.dumps(scopes),utcnow(),None,1));return token_id+"."+secret
    def identity(self):
        auth=request.headers.get("Authorization","")
        if auth.startswith("Bearer "):
            raw=auth[7:]; token_id,sep,secret=raw.partition(".")
            rows=self.db.rows("SELECT t.*,u.role,u.enabled AS user_enabled FROM api_tokens t JOIN users u ON u.username=t.owner WHERE token_id=? AND t.enabled=1",(token_id,)) if sep else []
            row=rows[0] if rows else None
            if row and row["user_enabled"] and hmac.compare_digest(row["secret_hash"],hash_token(secret)):
                self.db.execute("UPDATE api_tokens SET last_used=? WHERE token_id=?",(utcnow(),token_id));return {"username":row["owner"],"role":row["role"],"scopes":json.loads(row["scopes_json"]),"token":True}
            return None
        if session.get("username"):
            rows=self.db.rows("SELECT username,role FROM users WHERE username=? AND enabled=1",(session["username"],))
            if rows:return {"username":rows[0]["username"],"role":rows[0]["role"],"scopes":[],"token":False}
            session.clear();return None
        if not self.enabled:return {"username":"trusted-lan","role":"administrator","scopes":[],"token":False}
        return None
    def allowed(self,identity,permission):
        if not identity:return False
        if identity.get("token"):
            scope={"view":"read:fleet","history.read":"read:history","alerts.read":"read:alerts","alerts.write":"write:alerts","actions.execute":"execute:safe_actions","maintenance.write":"execute:safe_actions","device.power":"execute:safe_actions","config.write":"admin:config","users.write":"admin:config"}[permission]
            if scope not in identity["scopes"]:return False
        return ROLES.get(identity.get("role"),-1)>=ROLES[PERMISSIONS[permission]]

def install_security(app,manager):
    app.permanent_session_lifetime=timedelta(seconds=int(app.config.get("SESSION_TIMEOUT_SECONDS",3600)))
    app.config.setdefault("SESSION_COOKIE_HTTPONLY",True);app.config.setdefault("SESSION_COOKIE_SAMESITE","Lax")
    @app.before_request
    def authenticate_request():
        g.identity=manager.identity()
        if request.method in {"GET","HEAD","OPTIONS"} and "csrf_token" not in session:session["csrf_token"]=secrets.token_urlsafe(32)
        if request.endpoint=="login" and request.method=="POST":
            supplied=request.form.get("csrf_token")
            if not supplied or not hmac.compare_digest(str(supplied),str(session.get("csrf_token",""))):return jsonify({"error":"CSRF token missing or invalid"}),400
        public=request.endpoint in {"static","health","login"}
        if manager.enabled and not g.identity and not public:
            if request.path.startswith("/api/"):return jsonify({"error":"authentication required"}),401
            return redirect(url_for("login",next=request.full_path))
        permission=app.config.get("TOKEN_SCOPE_PERMISSIONS",{}).get(request.endpoint)
        if permission and g.identity and g.identity.get("token") and not manager.allowed(g.identity,permission):
            return jsonify({"error":"permission denied"}),403
        if request.method in {"POST","PUT","PATCH","DELETE"} and g.identity and not g.identity.get("token"):
            supplied=request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not supplied or not hmac.compare_digest(str(supplied),str(session.get("csrf_token",""))):return jsonify({"error":"CSRF token missing or invalid"}),400
    @app.after_request
    def headers(response):
        response.headers.setdefault("X-Content-Type-Options","nosniff");response.headers.setdefault("Referrer-Policy","same-origin")
        response.headers.setdefault("X-Frame-Options","DENY");response.headers.setdefault("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
        return response
    app.jinja_env.globals["csrf_token"]=lambda:session.get("csrf_token","")

def require(manager,permission):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if not manager.allowed(g.get("identity"),permission):return jsonify({"error":"permission denied"}),403
            return fn(*a,**kw)
        return wrapped
    return decorator
