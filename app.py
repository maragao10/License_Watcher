#!/usr/bin/env python3
"""
Cisco License Watcher (web)
- Cadastro de produtos e "consultas de licença" pela interface
- Dashboard com semáforo de validade
- Alerta no Webex (webhook ou bot) com agendamento semanal
Rodar: python app.py  ->  http://localhost:5000
"""
import os
import re
import sys
import json
import time
import secrets
import sqlite3
import datetime as dt
from contextlib import closing

import requests
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, flash, g, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

requests.packages.urllib3.disable_warnings()
UTC = dt.timezone.utc
DATA_DIR = os.environ.get("LW_DATA", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "licenses.db")
KEY_PATH = os.path.join(DATA_DIR, "secret.key")

app = Flask(__name__)
app.secret_key = os.environ.get("LW_SECRET") or secrets.token_hex(32)  # só p/ mensagens flash

# ---------- criptografia de segredos ----------
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "wb") as f:
        f.write(Fernet.generate_key())
    os.chmod(KEY_PATH, 0o600)
fernet = Fernet(open(KEY_PATH, "rb").read())
enc = lambda s: fernet.encrypt(s.encode()).decode() if s else ""
dec = lambda s: fernet.decrypt(s.encode()).decode() if s else ""

# ---------- modelos prontos (editáveis na tela; VALIDE endpoints na sua versão) ----------
TEMPLATES = {
    "custom": {"label": "Personalizado", "auth_type": "bearer", "checks": []},
}

# ---------- banco ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY, name TEXT, template TEXT, base_url TEXT, auth_type TEXT,
  username TEXT, password TEXT, token TEXT, header_name TEXT,
  login_path TEXT, token_field TEXT, token_header TEXT,
  verify_ssl INTEGER DEFAULT 1, enabled INTEGER DEFAULT 1, last_error TEXT, last_run TEXT);
CREATE TABLE IF NOT EXISTS checks(
  id INTEGER PRIMARY KEY, product_id INTEGER, label TEXT, path TEXT,
  items_path TEXT, name_field TEXT, expires_field TEXT);
CREATE TABLE IF NOT EXISTS licenses(
  id INTEGER PRIMARY KEY, product_id INTEGER, check_label TEXT, name TEXT, expires TEXT);
CREATE TABLE IF NOT EXISTS manual_licenses(
  id INTEGER PRIMARY KEY, product_id INTEGER, name TEXT, expires TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
DEFAULT_SETTINGS = {"warn_days": "30", "webex_mode": "webhook", "webex_webhook_url": "",
                    "webex_bot_token": "", "webex_room_id": "",
                    "schedule_day": "mon", "schedule_hour": "9", "send_ok": "0"}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def raw_db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(raw_db()) as c:
        c.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
        c.commit()


def get_settings(c=None):
    own = c is None
    c = c or raw_db()
    s = {r["key"]: r["value"] for r in c.execute("SELECT * FROM settings")}
    if own:
        c.close()
    return s


# ---------- coleta ----------
def dig(obj, path):
    if not path:
        return obj
    for part in path.split("."):
        if obj is None:
            return None
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def parse_date(v):
    if v in (None, "", 0, "0"):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.replace(".", "", 1).isdigit()):
        n = float(v)
        if n > 1e11:
            n /= 1000
        return dt.datetime.fromtimestamp(n, UTC)
    s = re.sub(r"\s+(UTC|GMT)$", "", str(v).strip()).replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        d = None
        for fmt in ("%d/%m/%Y", "%b %d, %Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d"):
            try:
                d = dt.datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def build_session(p):
    """Retorna (auth, headers) conforme o tipo de autenticação do produto."""
    verify = bool(p["verify_ssl"])
    t, user, pwd, tok = p["auth_type"], p["username"], dec(p["password"]), dec(p["token"])
    base = p["base_url"].rstrip("/")
    if t == "basic":
        return (user, pwd), {"Accept": "application/json"}
    if t == "bearer":
        return None, {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
    if t == "header":
        return None, {p["header_name"] or "X-API-Key": tok, "Accept": "application/json"}
    if t == "session":
        r = requests.post(base + p["login_path"], auth=(user, pwd), verify=verify, timeout=30)
        r.raise_for_status()
        token = dig(r.json(), p["token_field"] or "token")
        return None, {p["token_header"] or "X-Auth-Token": token, "Accept": "application/json"}
    return None, {"Accept": "application/json"}


def run_check(p, ch, auth, headers):
    base = p["base_url"].rstrip("/")
    r = requests.get(base + ch["path"], auth=auth, headers=headers,
                     verify=bool(p["verify_ssl"]), timeout=45)
    r.raise_for_status()
    data = r.json()
    items = dig(data, ch["items_path"])
    items = items if isinstance(items, list) else ([items] if items else [])
    out = []
    for it in items:
        exp = parse_date(dig(it, ch["expires_field"]))
        if exp:
            nf = ch["name_field"] or ""
            name = nf[1:] if nf.startswith("=") else dig(it, nf)
            out.append((str(name or "licença"), exp))
    return out


def collect_vcenter(p):
    """Lê as licenças via vSphere API (LicenseManager). Retorna [(nome, datetime)]."""
    import ssl
    from urllib.parse import urlparse
    from pyVim.connect import SmartConnect, Disconnect

    raw = p["base_url"].strip()
    u = urlparse(raw if "//" in raw else "https://" + raw)
    ctx = ssl.create_default_context() if p["verify_ssl"] else ssl._create_unverified_context()
    si = SmartConnect(host=u.hostname, port=u.port or 443, user=p["username"],
                      pwd=dec(p["password"]), sslContext=ctx)
    out = []
    try:
        now = dt.datetime.now(UTC)
        for lic in si.content.licenseManager.licenses:
            props = {kv.key: kv.value for kv in (lic.properties or [])}
            exp = props.get("expirationDate")
            if exp is None and isinstance(props.get("expirationHours"), (int, float)):
                exp = now + dt.timedelta(hours=props["expirationHours"])
            if exp is None:
                continue  # licença perpétua (Never)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            out.append((lic.name or lic.editionKey or "licença vSphere", exp))
        # Avaliação (Evaluation Mode) de hosts/vCenter: a validade fica na atribuição, não na lista
        try:
            lam = si.content.licenseManager.licenseAssignmentManager
            assigned = lam.QueryAssignedLicenses() if lam else []
        except Exception:
            assigned = []  # sem permissão ou API indisponível: segue só com a lista
        for a in assigned:
            al = a.assignedLicense
            props = {kv.key: kv.value for kv in (al.properties or [])}
            exp = props.get("expirationDate")
            if exp is None and isinstance(props.get("expirationHours"), (int, float)):
                exp = now + dt.timedelta(hours=props["expirationHours"],
                                         minutes=props.get("expirationMinutes") or 0)
            if exp is None:
                continue
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            out.append((f"{a.entityDisplayName or a.entityId} - {al.name or al.editionKey}", exp))
    finally:
        Disconnect(si)
    return out


def refresh_product(c, p):
    """Atualiza as licenças de um produto. Retorna mensagem de erro ou None."""
    c.execute("DELETE FROM licenses WHERE product_id=?", (p["id"],))
    errors = []
    if p["auth_type"] == "manual":
        for m in c.execute("SELECT * FROM manual_licenses WHERE product_id=?", (p["id"],)).fetchall():
            c.execute("INSERT INTO licenses(product_id,check_label,name,expires) VALUES(?,?,?,?)",
                      (p["id"], "Manual", m["name"], m["expires"]))
        c.execute("UPDATE products SET last_error=NULL, last_run=? WHERE id=?",
                  (dt.datetime.now(UTC).isoformat(), p["id"]))
        c.commit()
        return None
    if p["auth_type"] == "vcenter":
        try:
            for name, exp in collect_vcenter(p):
                c.execute("INSERT INTO licenses(product_id,check_label,name,expires) VALUES(?,?,?,?)",
                          (p["id"], "vSphere LicenseManager", name, exp.isoformat()))
        except Exception as e:
            errors.append(f"vCenter: {e}")
        err = "; ".join(errors) or None
        c.execute("UPDATE products SET last_error=?, last_run=? WHERE id=?",
                  (err, dt.datetime.now(UTC).isoformat(), p["id"]))
        c.commit()
        return err
    try:
        auth, headers = build_session(p)
    except Exception as e:
        errors.append(f"login: {e}")
        auth = headers = None
    if headers is not None:
        for ch in c.execute("SELECT * FROM checks WHERE product_id=?", (p["id"],)).fetchall():
            try:
                for name, exp in run_check(p, ch, auth, headers):
                    c.execute("INSERT INTO licenses(product_id,check_label,name,expires) VALUES(?,?,?,?)",
                              (p["id"], ch["label"], name, exp.isoformat()))
            except Exception as e:
                errors.append(f"{ch['label']}: {e}")
    err = "; ".join(errors) or None
    c.execute("UPDATE products SET last_error=?, last_run=? WHERE id=?",
              (err, dt.datetime.now(UTC).isoformat(), p["id"]))
    c.commit()
    return err


def refresh_all():
    with closing(raw_db()) as c:
        for p in c.execute("SELECT * FROM products WHERE enabled=1").fetchall():
            refresh_product(c, p)


def all_licenses(c):
    rows = c.execute("""SELECT l.*, p.name AS product FROM licenses l
                        JOIN products p ON p.id=l.product_id
                        WHERE p.enabled=1 ORDER BY l.expires""").fetchall()
    now = dt.datetime.now(UTC)
    out = []
    for r in rows:
        d = dict(r)
        d["days"] = (dt.datetime.fromisoformat(r["expires"]) - now).days
        out.append(d)
    return out


# ---------- Webex ----------
def send_webex(s, markdown):
    if s["webex_mode"] == "webhook":
        r = requests.post(s["webex_webhook_url"], json={"markdown": markdown}, timeout=30)
    else:
        r = requests.post("https://webexapis.com/v1/messages",
                          headers={"Authorization": f"Bearer {dec(s['webex_bot_token'])}"},
                          json={"roomId": s["webex_room_id"], "markdown": markdown}, timeout=30)
    r.raise_for_status()


def weekly_job():
    """Atualiza tudo e alerta o que está na janela (re-alerta toda semana)."""
    refresh_all()
    with closing(raw_db()) as c:
        s = get_settings(c)
        warn = int(s["warn_days"])
        exp = [l for l in all_licenses(c) if l["days"] <= warn]
        errs = [f"{p['name']}: {p['last_error']}" for p in
                c.execute("SELECT name,last_error FROM products WHERE enabled=1 AND last_error IS NOT NULL")]
    if exp or errs:
        send_webex(s, build_message(exp, errs, warn))
    elif s["send_ok"] == "1":
        send_webex(s, f"✅ Licenças Cisco: nenhuma expira nos próximos {warn} dias.")


def build_message(exp, errs, warn):
    lines = [f"## ⚠️ Licenças Cisco — expiram em até {warn} dias", ""]
    if exp:
        lines += ["| Dias | Produto | Licença | Expira em |", "|---|---|---|---|"]
        for l in exp:
            d = "**EXPIRADA**" if l["days"] < 0 else f"**{l['days']}**"
            dtv = dt.datetime.fromisoformat(l["expires"])
            lines.append(f"| {d} | {l['product']} | {l['name']} | {dtv:%d/%m/%Y} |")
    if errs:
        lines += ["", "**Falha ao consultar:**"] + [f"- {e}" for e in errs]
    return "\n".join(lines)


# ---------- agendador ----------
scheduler = BackgroundScheduler(timezone="America/Sao_Paulo")


def reschedule():
    s = get_settings()
    scheduler.add_job(weekly_job, "cron", id="weekly", replace_existing=True,
                      day_of_week=s["schedule_day"], hour=int(s["schedule_hour"]), minute=0)


# ---------- rotas ----------
@app.route("/")
def dashboard():
    c = db()
    s = get_settings(c)
    warn = int(s["warn_days"])
    lic = all_licenses(c)
    for l in lic:
        l["status"] = "expired" if l["days"] < 0 else "warn" if l["days"] <= warn else "ok"
    counts = {k: sum(1 for l in lic if l["status"] == k) for k in ("expired", "warn", "ok")}
    prods = c.execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("dashboard.html", lic=lic, counts=counts, warn=warn, prods=prods)


@app.post("/refresh")
def refresh():
    refresh_all()
    flash("Licenças atualizadas.")
    return redirect(url_for("dashboard"))


@app.route("/products")
def products():
    c = db()
    rows = c.execute("""SELECT p.*, (SELECT COUNT(*) FROM checks WHERE product_id=p.id) AS n_checks,
                        (SELECT COUNT(*) FROM licenses WHERE product_id=p.id) AS n_lic
                        FROM products p ORDER BY name""").fetchall()
    return render_template("products.html", rows=rows)


def save_product(pid=None):
    f = request.form
    c = db()
    old = c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone() if pid else None
    # campos de segredo em branco = manter o atual
    pwd = enc(f["password"]) if f.get("password") else (old["password"] if old else "")
    tok = enc(f["token"]) if f.get("token") else (old["token"] if old else "")
    vals = (f["name"], f.get("template", "custom"), f.get("base_url", "").strip(), f["auth_type"],
            f.get("username", ""), pwd, tok, f.get("header_name", ""), f.get("login_path", ""),
            f.get("token_field", ""), f.get("token_header", ""),
            1 if f.get("verify_ssl") else 0, 1 if f.get("enabled") else 0)
    if pid:
        c.execute("""UPDATE products SET name=?,template=?,base_url=?,auth_type=?,username=?,password=?,
                     token=?,header_name=?,login_path=?,token_field=?,token_header=?,verify_ssl=?,enabled=?
                     WHERE id=?""", vals + (pid,))
        c.execute("DELETE FROM checks WHERE product_id=?", (pid,))
    else:
        cur = c.execute("""INSERT INTO products(name,template,base_url,auth_type,username,password,token,
                           header_name,login_path,token_field,token_header,verify_ssl,enabled)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
        pid = cur.lastrowid
    cl, cp, ci, cn, ce = (f.getlist(k) for k in
                          ("c_label", "c_path", "c_items", "c_name", "c_expires"))
    is_manual = f.get("auth_type") == "manual"
    for row in zip(cl, cp, ci, cn, ce):
        if not is_manual and row[1].strip():
            c.execute("""INSERT INTO checks(product_id,label,path,items_path,name_field,expires_field)
                         VALUES(?,?,?,?,?,?)""", (pid, *[x.strip() for x in row]))
    c.execute("DELETE FROM manual_licenses WHERE product_id=?", (pid,))
    if is_manual:
        for name, date in zip(f.getlist("m_name"), f.getlist("m_date")):
            name, date = name.strip(), date.strip()
            if not name and not date:
                continue
            d = parse_date(date)
            if not name or d is None:
                flash(f"Licença manual ignorada (nome ou data inválidos): {name or '?'} / {date or '?'}")
                continue
            c.execute("INSERT INTO manual_licenses(product_id,name,expires) VALUES(?,?,?)",
                      (pid, name, d.isoformat()))
    c.commit()
    if is_manual:  # sem API: já atualiza o Dashboard ao salvar
        refresh_product(c, c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone())
    return pid


@app.route("/products/new", methods=["GET", "POST"])
def product_new():
    if request.method == "POST":
        pid = save_product()
        flash("Produto adicionado. Clique em Testar para validar.")
        return redirect(url_for("products"))
    return render_template("product_form.html", p=None, checks=[], manual=[], templates=TEMPLATES)


@app.route("/products/<int:pid>/edit", methods=["GET", "POST"])
def product_edit(pid):
    c = db()
    if request.method == "POST":
        save_product(pid)
        flash("Produto atualizado.")
        return redirect(url_for("products"))
    p = c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    checks = c.execute("SELECT * FROM checks WHERE product_id=?", (pid,)).fetchall()
    manual = [{"name": m["name"], "date": m["expires"][:10]} for m in
              c.execute("SELECT * FROM manual_licenses WHERE product_id=? ORDER BY id", (pid,))]
    return render_template("product_form.html", p=p, checks=[dict(x) for x in checks],
                           manual=manual, templates=TEMPLATES)


@app.post("/products/<int:pid>/delete")
def product_delete(pid):
    c = db()
    for t in ("licenses", "checks", "manual_licenses"):
        c.execute(f"DELETE FROM {t} WHERE product_id=?", (pid,))
    c.execute("DELETE FROM products WHERE id=?", (pid,))
    c.commit()
    flash("Produto removido.")
    return redirect(url_for("products"))


@app.post("/products/<int:pid>/test")
def product_test(pid):
    c = db()
    p = c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    err = refresh_product(c, p)
    n = c.execute("SELECT COUNT(*) FROM licenses WHERE product_id=?", (pid,)).fetchone()[0]
    if p["auth_type"] == "manual":
        flash(f"{p['name']}: {n} licenças manuais atualizadas.")
    else:
        flash(f"{p['name']}: {n} licenças lidas." + (f" Erros: {err}" if err else " Conexão OK."))
    return redirect(url_for("products"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    c = db()
    if request.method == "POST":
        f = request.form
        pairs = {k: f.get(k, "") for k in ("warn_days", "webex_mode", "webex_webhook_url",
                                            "webex_room_id", "schedule_day", "schedule_hour")}
        pairs["send_ok"] = "1" if f.get("send_ok") else "0"
        if f.get("webex_bot_token"):
            pairs["webex_bot_token"] = enc(f["webex_bot_token"])
        for k, v in pairs.items():
            c.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
        c.commit()
        reschedule()
        flash("Configurações salvas.")
        if f.get("action") == "test":
            try:
                send_webex(get_settings(c), "✅ Teste do Cisco License Watcher.")
                flash("Mensagem de teste enviada ao Webex.")
            except Exception as e:
                flash(f"Falha no Webex: {e}")
        return redirect(url_for("settings"))
    return render_template("settings.html", s=get_settings(c))


@app.post("/alert-now")
def alert_now():
    try:
        weekly_job()
        flash("Verificação executada e alerta enviado (se houver algo na janela).")
    except Exception as e:
        flash(f"Erro: {e}")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    reschedule()
    scheduler.start()
    app.run(host=os.environ.get("LW_HOST", "127.0.0.1"), port=int(os.environ.get("LW_PORT", 5000)))
