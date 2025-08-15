import os, subprocess, shlex, json, base64, time, hashlib, shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

import requests
import jwt
from fastapi import FastAPI, UploadFile, File, Form, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from jinja2 import Template

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]

app = FastAPI(title="Person OSINT API (Enterprise)", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/files", StaticFiles(directory=str(DATA_DIR), html=False), name="files")

# ---------- Simple in-memory rate limiting (per IP) ----------
RATE_LIMIT = int(os.getenv("RATELIMIT_PER_MIN", "60"))
_traffic: Dict[str, Dict[str, Any]] = {}  # ip -> {count:int, window_start:float}

def rate_limit_dep(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    rec = _traffic.get(ip, {"count":0, "window_start":now})
    if now - rec["window_start"] >= 60:
        rec = {"count":0, "window_start":now}
    rec["count"] += 1
    _traffic[ip] = rec
    if rec["count"] > RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return

# ---------- Auth ----------
JWT_SECRET = os.getenv("JWT_SECRET", "changeme-supersecret")
API_TOKEN = os.getenv("API_TOKEN")
BASIC_USER = os.getenv("BASIC_AUTH_USER")
BASIC_PASS = os.getenv("BASIC_AUTH_PASS")

USERS_JSON = os.getenv("USERS_JSON", "[]")
try:
    USERS = json.loads(USERS_JSON)
except Exception:
    USERS = []

def _unauthorized():
    headers = {"WWW-Authenticate": "Basic realm=\"OSINT\""}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized", headers=headers)

def _jwt_from_header(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def _basic_ok(request: Request) -> bool:
    auth = request.headers.get("authorization", "")
    if not (BASIC_USER and BASIC_PASS) or not auth.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8")
        u, p = raw.split(":", 1)
        return (u == BASIC_USER and p == BASIC_PASS)
    except Exception:
        return False

def auth_required(role: Optional[str] = None):
    def _dep(request: Request):
        token = _jwt_from_header(request)
        if token:
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                if role and payload.get("role") not in [role, "admin"]:
                    raise HTTPException(status_code=403, detail="Insufficient role")
                return payload
            except Exception:
                _unauthorized()
        if API_TOKEN:
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {API_TOKEN}":
                return {"user":"token", "role":"admin"}
        if _basic_ok(request):
            return {"user":"basic", "role":"admin"}
        _unauthorized()
    return _dep

@app.post("/auth/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = next((u for u in USERS if u.get("username")==username and u.get("password")==password), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {"sub": username, "role": user.get("role","viewer"), "exp": datetime.utcnow() + timedelta(hours=12)}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"ok": True, "token": token, "role": payload["role"]}

# ---------- Helpers ----------
def ts():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def run_cmd(cmd: str):
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=None)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", str(e)

def case_dir(case_id: Optional[str]) -> Path:
    if not case_id:
        return DATA_DIR
    p = DATA_DIR / "cases" / case_id
    p.mkdir(parents=True, exist_ok=True)
    return p

def record(case_id: Optional[str], entry: Dict[str, Any]):
    if not case_id:
        return
    meta = case_dir(case_id) / "meta.json"
    existing = []
    if meta.exists():
        try:
            existing = json.loads(meta.read_text(encoding="utf-8"))
        except Exception:
            existing = []
    entry["time"] = datetime.now().isoformat()
    existing.append(entry)
    meta.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

# ---------- Core tools ----------
@app.get("/health")
def health():
    return {"ok": True, "time": datetime.now().isoformat()}

@app.post("/username")
def check_username(username: str = Form(...), timeout: int = Form(10), case_id: Optional[str] = Form(None),
                   _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    html_path = case_dir(case_id) / f"{username}_maigret.html"
    json_path = case_dir(case_id) / f"{username}_maigret.json"
    cmd = f"maigret {shlex.quote(username)} --timeout {timeout} --html {html_path} --json {json_path} --no-color"
    code, out, err = run_cmd(cmd)
    entry = {"tool":"maigret","ok": code==0, "username": username,
             "html": f"/files/{html_path.relative_to(DATA_DIR)}" if html_path.exists() else None,
             "json": f"/files/{json_path.relative_to(DATA_DIR)}" if json_path.exists() else None,
             "stdout": (out or "")[-2000:], "stderr": (err or "")[-2000:]}
    record(case_id, entry)
    return entry

@app.post("/email")
def check_email(email: str = Form(...), only_used: bool = Form(True), case_id: Optional[str] = Form(None),
                _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    suffix = "_onlyused" if only_used else ""
    out_path = case_dir(case_id) / f"{email.replace('@','_at_')}_holehe{suffix}.txt"
    flag = "--only-used" if only_used else ""
    cmd = f"holehe {shlex.quote(email)} {flag} --no-color"
    code, out, err = run_cmd(cmd)
    out_path.write_text(out or "", encoding="utf-8")
    entry = {"tool":"holehe","ok": code==0,"email": email,"txt": f"/files/{out_path.relative_to(DATA_DIR)}",
             "stdout": (out or "")[-2000:],"stderr": (err or "")[-2000:]}
    record(case_id, entry)
    return entry

@app.post("/exif")
async def exif(file: UploadFile = File(...), case_id: Optional[str] = Form(None),
               _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    raw_name = Path(file.filename).name
    buf = await file.read()
    up_path = case_dir(case_id) / f"upload_{ts()}_{raw_name}"
    up_path.write_bytes(buf)
    sha256 = hashlib.sha256(buf).hexdigest()
    size = len(buf)

    code, out, err = run_cmd(f"exiftool -json {shlex.quote(str(up_path))}")
    json_path = case_dir(case_id) / f"{raw_name}_exif.json"
    try:
        data = json.loads(out) if out else []
    except Exception as e:
        data = [{"error": f"parse failed: {e}"}]
    if isinstance(data, list) and data:
        data[0]["ChainOfCustody_SHA256"] = sha256
        data[0]["ChainOfCustody_SizeBytes"] = size
        data[0]["ChainOfCustody_StoredPath"] = str(up_path)
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    entry = {"tool":"exif","ok": code==0,"upload": f"/files/{up_path.relative_to(DATA_DIR)}","json": f"/files/{json_path.relative_to(DATA_DIR)}",
             "sha256": sha256, "size_bytes": size, "stderr": (err or "")[-2000:]}
    record(case_id, entry)
    return entry

@app.post("/wayback")
def wayback(url: str = Form(...), case_id: Optional[str] = Form(None),
            _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    def lookup(u: str):
        try:
            r = requests.get("https://web.archive.org/cdx/search/cdx",
                             params={"url": u, "output": "json", "limit": 5, "filter": "statuscode:200", "collapse": "digest"},
                             timeout=30)
            snapshots = []
            if r.ok:
                rows = r.json()
                for row in rows[1:]:
                    snapshots.append({"timestamp": row[1],"original": row[2],"wayback": f"https://web.archive.org/web/{row[1]}/{row[2]}"})
            return {"ok": True, "snapshots": snapshots}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def save(u: str):
        try:
            r = requests.get(f"https://web.archive.org/save/{u}", timeout=60, allow_redirects=True)
            return {"ok": True, "status_code": r.status_code}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    looked = lookup(url)
    saved = save(url)
    out_json = case_dir(case_id) / f"{ts()}_wayback.json"
    out_json.write_text(json.dumps({"lookup": looked, "save": saved}, indent=2, ensure_ascii=False), encoding="utf-8")
    entry = {"tool":"wayback","ok": looked.get("ok", False),"url": url,"json": f"/files/{out_json.relative_to(DATA_DIR)}","lookup": looked,"save": saved}
    record(case_id, entry)
    return entry

@app.post("/phone")
def phone(number: str = Form(...), case_id: Optional[str] = Form(None),
          _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    out_path = case_dir(case_id) / f"phone_{number.replace('+','plus').replace(' ','_').replace('/','_')}_{ts()}.txt"
    cmd = f"phoneinfoga scan -n {shlex.quote(number)}"
    code, out, err = run_cmd(cmd)
    content = ""
    if out: content += out
    if err: content += "\n[stderr]\n" + err
    out_path.write_text(content, encoding="utf-8")
    entry = {"tool":"phoneinfoga","ok": code==0,"number": number,"txt": f"/files/{out_path.relative_to(DATA_DIR)}",
             "stdout": (out or "")[-2000:],"stderr": (err or "")[-2000:]}
    record(case_id, entry)
    return entry

# ---------- External APIs ----------
@app.post("/hibp")
def hibp(email: str = Form(...), truncate: bool = Form(False), case_id: Optional[str] = Form(None),
         _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        raise HTTPException(status_code=400, detail="HIBP_API_KEY not set")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": "person-osint-web"}
    params = {"truncateResponse": "true" if truncate else "false"}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    if r.status_code == 404:
        data = []
    else:
        r.raise_for_status()
        data = r.json()
    out_path = case_dir(case_id) / f"hibp_{email.replace('@','_at_')}_{ts()}.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    entry = {"tool":"hibp","ok": True,"email": email,"json": f"/files/{out_path.relative_to(DATA_DIR)}","count": len(data)}
    record(case_id, entry)
    return entry

@app.post("/hunter")
def hunter(email: str = Form(...), case_id: Optional[str] = Form(None),
          _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    key = os.getenv("HUNTER_API_KEY")
    if not key:
        raise HTTPException(status_code=400, detail="HUNTER_API_KEY not set")
    r = requests.get("https://api.hunter.io/v2/email-verifier", params={"email": email, "api_key": key}, timeout=30)
    r.raise_for_status()
    data = r.json()
    out_path = case_dir(case_id) / f"hunter_{email.replace('@','_at_')}_{ts()}.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    entry = {"tool":"hunter","ok": True,"email": email,"json": f"/files/{out_path.relative_to(DATA_DIR)}"}
    record(case_id, entry)
    return entry

@app.post("/clearbit")
def clearbit(email: str = Form(...), case_id: Optional[str] = Form(None),
             _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    key = os.getenv("CLEARBIT_API_KEY")
    if not key:
        raise HTTPException(status_code=400, detail="CLEARBIT_API_KEY not set")
    headers = {"Authorization": f"Bearer {key}"}
    r = requests.get("https://person.clearbit.com/v2/combined/find", params={"email": email}, headers=headers, timeout=30)
    if r.status_code == 404:
        data = {"found": False}
    else:
        r.raise_for_status()
        data = r.json()
        data["found"] = True
    out_path = case_dir(case_id) / f"clearbit_{email.replace('@','_at_')}_{ts()}.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    entry = {"tool":"clearbit","ok": True,"email": email,"json": f"/files/{out_path.relative_to(DATA_DIR)}","found": data.get("found", False)}
    record(case_id, entry)
    return entry

# ---------- Report (HTML + PDF) ----------
REPORT_TMPL = Template(r"""
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Person OSINT Report - {{ case_id }}</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:20px}
.container{max-width:1000px;margin:0 auto}
h1{margin:0 0 6px 0} .muted{color:#94a3b8}
.card{background:#0f172a;border:1px solid rgba(255,255,255,.08);padding:14px;border-radius:14px;margin:12px 0}
pre{background:#020617;border:1px solid rgba(255,255,255,.06);padding:10px;border-radius:10px;overflow:auto;max-height:300px}
a{color:#22d3ee}
.bad{color:#ef4444}.ok{color:#10b981}
small{color:#94a3b8}
table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px}
.kv div{padding:4px 0}
</style>
</head>
<body>
<div class="container">
  <h1>Person OSINT Report</h1>
  <div class="muted">Case: <b>{{ case_id }}</b> • Generated: {{ now }}</div>

  <div class="card">
    <h3>Timeline</h3>
    <table>
      <tr><th>Waktu</th><th>Tool</th><th>Ringkas</th></tr>
      {% for item in items %}
      <tr>
        <td>{{ item.time }}</td>
        <td>{{ item.tool }}</td>
        <td>
          {% if item.tool=='maigret' %}Username: {{ item.username }}
          {% elif item.tool=='holehe' %}Email: {{ item.email }}
          {% elif item.tool=='exif' %}File: {{ item.upload }}
          {% elif item.tool=='phoneinfoga' %}Number: {{ item.number }}
          {% elif item.tool=='wayback' %}URL: {{ item.url }}
          {% elif item.tool in ['hibp','hunter','clearbit'] %}Email: {{ item.email }}
          {% else %}-{% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h3>Chain of Custody</h3>
    <div class="kv">
      <div>Case ID</div><div>{{ case_id }}</div>
      <div>Total Artefak</div><div>{{ items|length }}</div>
      <div>Generated</div><div>{{ now }}</div>
      <div>Storage</div><div>/files/cases/{{ case_id }}/</div>
    </div>
    <p class="muted">Catatan: unggahan file mencantumkan SHA-256 & ukuran pada metadata EXIF JSON.</p>
  </div>

  {% for item in items %}
  <div class="card">
    <div><b>{{ item.tool|upper }}</b> • <span class="{{ 'ok' if item.ok else 'bad' }}">{{ 'OK' if item.ok else 'FAIL' }}</span> • <small>{{ item.time }}</small></div>
    <ul>
      {% for k,v in item.items() %}
        {% if k not in ['tool','ok','time','stdout','stderr'] %}
          <li><b>{{ k }}</b>: {% if v and v|string.startswith('/files/') %}<a href="{{ base }}{{ v }}" target="_blank">{{ v.split('/')[-1] }}</a>{% else %}{{ v }}{% endif %}</li>
        {% endif %}
      {% endfor %}
    </ul>
    {% if item.stdout %}<pre>{{ item.stdout }}</pre>{% endif %}
    {% if item.stderr %}<pre>{{ item.stderr }}</pre>{% endif %}
  </div>
  {% endfor %}

  <div class="card">
    <b>Artifacts directory:</b>
    <a href="{{ base }}/files/cases/{{ case_id }}" target="_blank">/files/cases/{{ case_id }}</a>
  </div>
</div>
</body>
</html>
""")

@app.post("/report")
def report(case_id: str = Form(...), _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    p = case_dir(case_id)
    meta = p / "meta.json"
    if not meta.exists():
        return JSONResponse({"ok": False, "error": "No records for this case_id yet."}, status_code=404)
    data = json.loads(meta.read_text(encoding="utf-8"))
    try:
        data.sort(key=lambda x: x.get("time",""))
    except Exception:
        pass
    html_path = p / "report.html"
    html = REPORT_TMPL.render(case_id=case_id, items=data, now=datetime.now().isoformat(), base="")
    html_path.write_text(html, encoding="utf-8")
    return {"ok": True, "html": f"/files/{html_path.relative_to(DATA_DIR)}", "count": len(data)}

def _chromium_bin() -> str:
    for b in ["chromium", "chromium-browser", "google-chrome", "chrome"]:
        path = shutil.which(b)
        if path:
            return path
    return "chromium"

@app.post("/report_pdf")
def report_pdf(case_id: str = Form(...), _rl=Depends(rate_limit_dep), _auth=Depends(auth_required("analyst"))):
    p = case_dir(case_id)
    html_path = p / "report.html"
    if not html_path.exists():
        _ = report(case_id)
    html_path = p / "report.html"
    pdf_path = p / "report.pdf"
    chrome = _chromium_bin()
    file_url = f"file://{html_path}"
    cmd = f"{chrome} --headless --disable-gpu --no-sandbox --print-to-pdf={pdf_path} {file_url}"
    code, out, err = run_cmd(cmd)
    if code != 0:
        return JSONResponse({"ok": False, "error": f"PDF generation failed: {err or out}"}, status_code=500)
    return {"ok": True, "pdf": f"/files/{pdf_path.relative_to(DATA_DIR)}"}
