from flask import Flask, request, redirect, url_for, session, render_template_string, flash, Response
import sqlite3, os, hashlib, secrets, csv, io
from datetime import datetime, date, timedelta
from functools import wraps

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "buildai.db")
VERSION = "1.3.2"
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "buildai-change-this-secret")


def now():
    return datetime.now().isoformat(timespec="seconds")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
        return secrets.compare_digest(check, digest)
    except Exception:
        return False


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customers(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT,
        email TEXT, address TEXT, rating TEXT NOT NULL DEFAULT 'normal', notes TEXT,
        created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS projects(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, customer TEXT,
        customer_id INTEGER, location TEXT, budget REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active', start_date TEXT, end_date TEXT,
        notes TEXT, created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS expenses(
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, user_id INTEGER NOT NULL,
        category TEXT NOT NULL, description TEXT NOT NULL, amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', expense_date TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incomes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, user_id INTEGER NOT NULL,
        description TEXT NOT NULL, amount REAL NOT NULL, income_date TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, user_id INTEGER NOT NULL,
        work_done TEXT NOT NULL, workers_count INTEGER NOT NULL DEFAULT 0,
        materials_used TEXT, issues TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS contracts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, contract_no TEXT UNIQUE NOT NULL,
        customer_id INTEGER, project_id INTEGER, title TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0, start_date TEXT, end_date TEXT,
        status TEXT NOT NULL DEFAULT 'draft', terms TEXT, created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invoices(
        id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_no TEXT UNIQUE NOT NULL,
        customer_id INTEGER, project_id INTEGER, issue_date TEXT NOT NULL, due_date TEXT,
        description TEXT NOT NULL, subtotal REAL NOT NULL DEFAULT 0,
        tax_rate REAL NOT NULL DEFAULT 5, tax_amount REAL NOT NULL DEFAULT 0,
        total REAL NOT NULL DEFAULT 0, paid_amount REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'unpaid', created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS suppliers(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT,
        email TEXT, address TEXT, category TEXT, balance REAL NOT NULL DEFAULT 0,
        notes TEXT, created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS employees(
        id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, phone TEXT,
        job_title TEXT, salary_type TEXT NOT NULL DEFAULT 'monthly', salary_rate REAL NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1, notes TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS payroll(
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL, period TEXT NOT NULL,
        base_amount REAL NOT NULL DEFAULT 0, bonus REAL NOT NULL DEFAULT 0, deduction REAL NOT NULL DEFAULT 0,
        net_amount REAL NOT NULL DEFAULT 0, paid_date TEXT, status TEXT NOT NULL DEFAULT 'unpaid',
        notes TEXT, created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inventory(
        id INTEGER PRIMARY KEY AUTOINCREMENT, item_name TEXT NOT NULL, unit TEXT NOT NULL DEFAULT 'pcs',
        quantity REAL NOT NULL DEFAULT 0, min_quantity REAL NOT NULL DEFAULT 0, unit_cost REAL NOT NULL DEFAULT 0,
        supplier_id INTEGER, location TEXT, notes TEXT, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inventory_movements(
        id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, movement_type TEXT NOT NULL,
        quantity REAL NOT NULL, project_id INTEGER, note TEXT, user_id INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS accounts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, account_type TEXT NOT NULL DEFAULT 'cash',
        opening_balance REAL NOT NULL DEFAULT 0, notes TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS account_transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, transaction_type TEXT NOT NULL,
        amount REAL NOT NULL, reference_type TEXT, reference_id INTEGER, description TEXT,
        transaction_date TEXT NOT NULL, created_by INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
        details TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS personal_transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL, category TEXT NOT NULL, description TEXT,
        amount REAL NOT NULL, transaction_date TEXT NOT NULL, created_at TEXT NOT NULL
    );
    """)
    # Safe migrations for databases created by version 1.0
    migrations = [
        ("projects", "customer_id", "INTEGER"), ("projects", "start_date", "TEXT"),
        ("projects", "end_date", "TEXT"), ("projects", "notes", "TEXT"),
        ("expenses", "expense_date", "TEXT"), ("incomes", "income_date", "TEXT")
    ]
    for table, column, definition in migrations:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    if not conn.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        conn.execute("INSERT INTO users(full_name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                     ("مالک / Owner", "admin", hash_password("123456"), "admin", now()))
    if not conn.execute("SELECT id FROM accounts LIMIT 1").fetchone():
        conn.execute("INSERT INTO accounts(name,account_type,opening_balance,notes,active,created_at) VALUES(?,?,?,?,1,?)",
                     ("صندوق اصلی / Main Cash", "cash", 0, "حساب پیش‌فرض", now()))
    conn.commit(); conn.close()


def log_action(action, details=""):
    conn = get_db(); conn.execute("INSERT INTO activity(user_id,action,details,created_at) VALUES(?,?,?,?)",
        (session.get("user_id"), action, details, now())); conn.commit(); conn.close()


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                flash("دسترسی ندارید / Access denied")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapped
    return deco


def money(v):
    try: return f"AED {float(v):,.2f}"
    except: return "AED 0.00"

app.jinja_env.filters["money"] = money

STYLE = """
<style>
:root{--bg:#f3f6fb;--card:#fff;--ink:#0d1b38;--muted:#71809a;--blue:#1262e9;--nav:#061936;--ok:#12a56f;--bad:#ef4444;--purple:#7048e8;--orange:#f59e0b;--personal:#0b1735}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;color:var(--ink)}a{color:inherit}
.topbar{height:64px;background:linear-gradient(90deg,#06152f,#071b3b);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 20px;position:sticky;top:0;z-index:50;box-shadow:0 5px 18px #04112a22}.brand{font-size:25px;font-weight:950;letter-spacing:-.5px}.version{font-size:11px;background:#22c55e24;color:#55e58a;padding:5px 9px;border-radius:20px;margin-inline-start:6px}.userbox{font-size:13px;display:flex;gap:10px;align-items:center}.hamb{display:none;border:0;background:#ffffff14;color:#fff;border-radius:10px;padding:8px 11px;font-size:20px}
.shell{display:grid;grid-template-columns:205px minmax(0,3fr) minmax(285px,1fr);min-height:calc(100vh - 64px)}.sidebar{background:linear-gradient(180deg,#09234a 0%,#06152f 70%);color:#fff;padding:15px 11px;position:sticky;top:64px;height:calc(100vh - 64px);overflow:auto}.menu-title{font-size:12px;color:#b8c6df;padding:9px 11px 13px;border-bottom:1px solid #ffffff16;margin-bottom:8px}.nav{display:grid;gap:5px}.nav a{color:#fff;text-decoration:none;padding:11px 12px;border-radius:11px;font-size:13px;display:flex;align-items:center;gap:8px;white-space:nowrap}.nav a:hover{background:#ffffff15}.nav a:first-child{background:linear-gradient(135deg,#1365f1,#3478ff);box-shadow:0 8px 20px #1262e933}
.company{padding:16px;min-width:0}.personal{background:linear-gradient(180deg,#171b46,#07152f);color:#fff;padding:15px;min-width:0}.personal .card{background:#ffffff0d;color:#fff;border:1px solid #ffffff0e;box-shadow:none}.personal .muted{color:#b9c4da}.personal h2,.personal h3{color:#fff}.personal table{color:#fff}.personal th{color:#b8c2da}.personal td,.personal th{border-color:#ffffff12}
.wrap{max-width:none;margin:0;padding:0}.grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.grid4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.dash2{display:grid;grid-template-columns:1.05fr 1.25fr;gap:12px}.card{background:#fff;border-radius:16px;padding:15px;box-shadow:0 7px 22px #1d2d4d10;border:1px solid #e8edf5}.kpi{position:relative;overflow:hidden}.kpi:before{content:"";position:absolute;inset-inline-start:0;top:0;bottom:0;width:5px;background:var(--blue)}.kpi.green:before{background:var(--ok)}.kpi.red:before{background:var(--bad)}.kpi.purple:before{background:var(--purple)}.kpi.orange:before{background:var(--orange)}.kpi.blue:before{background:var(--blue)}.kpi-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;font-size:20px;background:#edf3ff;margin-bottom:8px}.green .kpi-icon{background:#e7f9f1}.red .kpi-icon{background:#ffeded}.purple .kpi-icon{background:#f0ebff}.orange .kpi-icon{background:#fff3df}.big{font-size:23px;font-weight:950;margin-top:6px;white-space:nowrap}.muted{color:var(--muted);font-size:12px}.section{margin-top:13px}h2{margin:0 0 11px;font-size:17px}h3{margin:0 0 8px}.section-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.section-head a{font-size:12px;color:var(--blue);text-decoration:none;font-weight:800}
.quick-row{display:grid;grid-template-columns:repeat(9,minmax(90px,1fr));gap:8px}.quick{display:block;text-decoration:none;transition:.15s;text-align:center;padding:13px 7px}.quick:hover{transform:translateY(-2px)}.quick .qicon{font-size:25px;margin-bottom:7px}.quick.blue{background:#eaf1ff}.quick.green{background:#e9fbf3}.quick.purple{background:#f1ecff}.quick.orange{background:#fff3e4}.quick.red{background:#ffeded}.quick.teal{background:#e8fbf8}
.chart{height:220px;position:relative;padding:18px 8px 8px;border-radius:12px;background:linear-gradient(180deg,#fff,#fafcff);overflow:hidden}.chart-grid{position:absolute;inset:20px 10px 28px 10px;background:repeating-linear-gradient(to bottom,transparent 0,transparent 32px,#dbe4f0 33px)}.chart svg{position:absolute;inset:10px;width:calc(100% - 20px);height:calc(100% - 25px)}.legend{display:flex;gap:16px;font-size:11px;margin-bottom:4px}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-left:5px}.progress{height:8px;background:#e7edf5;border-radius:20px;overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,#16a36e,#22c55e);border-radius:20px}
form{display:grid;gap:12px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}label{display:block;font-size:13px;color:var(--muted);font-weight:700;margin-bottom:6px}input,select,textarea{width:100%;padding:11px;border:1px solid #d7dfec;border-radius:11px;font:inherit;background:#fff}textarea{min-height:90px}.btn{border:0;background:var(--blue);color:#fff;padding:10px 13px;border-radius:11px;text-decoration:none;font-weight:800;cursor:pointer;display:inline-block}.btn.ok{background:var(--ok)}.btn.bad{background:var(--bad)}.btn.sm{padding:6px 9px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:10px 8px;border-bottom:1px solid #e6ebf2;text-align:right}th{color:var(--muted);font-size:10px}.badge{padding:5px 8px;border-radius:20px;font-size:10px;background:#e8eef8}.badge.approved,.badge.paid,.badge.good,.badge.active{background:#dcf8eb;color:#08734c}.badge.pending,.badge.normal,.badge.partial{background:#fff1d6;color:#996000}.badge.rejected,.badge.bad,.badge.overdue,.badge.unpaid{background:#ffe1e5;color:#a51d31}.flash{background:#fff3cd;padding:11px;border-radius:10px;margin-bottom:12px}.login{max-width:430px;margin:70px auto;padding:16px}.ltr{direction:ltr;text-align:left}.personal-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.personal-actions .btn{font-size:11px;text-align:center;padding:10px 5px}.personal-summary{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.personal-summary .card{padding:12px}.personal-summary .big{font-size:16px}.expense-bar{height:9px;border-radius:10px;background:#ffffff18;overflow:hidden}.expense-bar span{display:block;height:100%;background:linear-gradient(90deg,#6d5dfc,#ee4d8a)}.mobile-tabs{display:none}
@media(max-width:1260px){.shell{grid-template-columns:185px minmax(0,3fr) minmax(250px,1fr)}.grid{grid-template-columns:repeat(3,1fr)}.quick-row{grid-template-columns:repeat(5,1fr)}}
@media(max-width:900px){.topbar{height:58px}.hamb{display:block}.shell{grid-template-columns:1fr}.sidebar{position:fixed;z-index:60;top:58px;right:-230px;width:220px;height:calc(100vh - 58px);transition:.2s}.sidebar.open{right:0}.company{padding:11px}.personal{order:3}.grid,.grid4{grid-template-columns:repeat(2,1fr)}.grid3,.dash2{grid-template-columns:1fr}.quick-row{grid-template-columns:repeat(3,1fr)}.row,.row3{grid-template-columns:1fr}.mobile-tabs{display:flex;gap:8px;padding:8px 11px;background:#fff;position:sticky;top:58px;z-index:35;border-bottom:1px solid #e5eaf2}.mobile-tabs a{flex:1;text-align:center;text-decoration:none;padding:9px;border-radius:10px;background:#edf3ff;color:#123}.mobile-tabs a:last-child{background:#171b46;color:#fff}}
@media(max-width:560px){.grid,.grid4{grid-template-columns:1fr}.quick-row{grid-template-columns:repeat(2,1fr)}.personal-summary{grid-template-columns:1fr 1fr}.big{font-size:21px}.company{padding:10px}.card{border-radius:15px}.topbar{padding:0 12px}.brand{font-size:21px}}
@media(orientation:landscape) and (max-height:600px){.topbar{height:52px}.shell{min-height:calc(100vh - 52px);grid-template-columns:180px minmax(0,3fr) minmax(250px,1fr)}.sidebar{display:block;position:sticky;top:52px;right:auto;width:auto;height:calc(100vh - 52px)}.company{padding:10px}.personal{display:block;padding:10px}.hamb,.mobile-tabs{display:none}.grid{grid-template-columns:repeat(5,1fr)}.grid4{grid-template-columns:repeat(4,1fr)}.dash2{grid-template-columns:1.05fr 1.25fr}.quick-row{grid-template-columns:repeat(5,1fr)}.card{padding:11px}.big{font-size:18px}.chart{height:175px}.nav a{padding:8px 9px;font-size:11px}.menu-title{padding:5px 8px}.personal .section{margin-top:8px}}

/* v1.3.2 responsive company-first layout */
html{overflow-x:hidden}body{background:#eef3fa}.topbar{width:96%;margin:0 auto;border-radius:0 0 16px 16px}.shell{width:96%;margin:0 auto;grid-template-columns:205px minmax(0,1fr);transition:padding-right .25s ease}.company{min-width:0;transition:margin-right .25s ease;padding:16px}.personal{display:none}.personal-toggle{border:1px solid #ffffff24;background:#ffffff12;color:#fff;border-radius:12px;padding:8px 12px;font-weight:800;cursor:pointer;display:flex;align-items:center;gap:7px}.personal-toggle:hover{background:#ffffff20}.personal-drawer{position:fixed;z-index:80;top:70px;right:2%;bottom:12px;width:clamp(245px,19.2vw,360px);background:linear-gradient(180deg,#0c1b3d,#101a3f);color:#fff;border-radius:17px;box-shadow:0 24px 60px #02081755;overflow:auto;padding:13px;transform:translateX(calc(100% + 40px));opacity:0;pointer-events:none;transition:.25s ease}.personal-drawer.open{transform:translateX(0);opacity:1;pointer-events:auto}.personal-drawer .drawer-head{display:flex;align-items:center;justify-content:space-between;position:sticky;top:-13px;margin:-13px -13px 12px;padding:13px;background:#0c1b3df2;backdrop-filter:blur(10px);z-index:3;border-bottom:1px solid #ffffff18}.personal-drawer .drawer-close{border:0;background:#ffffff14;color:#fff;border-radius:10px;width:34px;height:34px;font-size:20px}.personal-drawer .card{background:#ffffff0d;border:1px solid #ffffff12;color:#fff;box-shadow:none}.personal-drawer .muted{color:#b8c6df}.personal-drawer table td,.personal-drawer table th{border-color:#ffffff15}.personal-drawer .big{font-size:17px}.personal-drawer h2{font-size:18px;margin:0}.period-lines{display:grid;gap:6px;margin-top:10px;padding-top:8px;border-top:1px solid #e7edf5}.period-line{display:flex;justify-content:space-between;gap:8px;font-size:11px}.period-line b{white-space:nowrap}.kpi .big{font-size:22px}.kpi{min-height:178px}.dashboard-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.dashboard-title h1{font-size:22px;margin:0}.today-chip{background:#fff;border:1px solid #dfe7f2;border-radius:12px;padding:8px 11px;font-size:12px;color:var(--muted)}
@media(min-width:901px){body.personal-open .company{margin-right:clamp(255px,20vw,375px)}}
@media(max-width:900px){.topbar,.shell{width:100%;border-radius:0}.personal-toggle span:last-child{display:none}.personal-drawer{top:64px;right:2.5%;width:85vw;max-width:390px}.company{padding:10px}.kpi{min-height:150px}.dashboard-title h1{font-size:18px}}
@media(orientation:landscape) and (max-height:600px){.topbar,.shell{width:96%}.personal-drawer{top:58px;width:clamp(230px,19.2vw,300px);font-size:11px}.personal-drawer .card{padding:9px}.personal-drawer .big{font-size:14px}body.personal-open .company{margin-right:clamp(240px,20vw,310px)}.kpi{min-height:135px}.period-lines{gap:3px}.period-line{font-size:9px}}

</style>"""

BASE = """<!doctype html><html lang="fa" dir="rtl"><head><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,viewport-fit=cover"><meta charset="utf-8"><title>{{title}} | BuildAI ERP</title>""" + STYLE + """</head><body>
{% if session.get('user_id') %}<div class="topbar"><button class="hamb" onclick="document.querySelector('.sidebar').classList.toggle('open')">☰</button><div class="brand">BuildAI ERP <span class="version">v{{version}}</span></div><div class="userbox"><button class="personal-toggle" id="personalToggle" type="button" onclick="togglePersonal()"><span>👤</span><span>حساب شخصی / Personal Account</span></button><span>مالک / Owner</span></div></div><div class="shell"><aside class="sidebar"><div class="menu-title">منوی اصلی شرکت / Company Menu</div><div class="nav">
<a href="{{url_for('dashboard')}}">▣ داشبورد / Dashboard</a><a href="{{url_for('projects')}}">▥ پروژه‌ها / Projects</a><a href="{{url_for('customers')}}">♙ مشتریان / Customers</a><a href="{{url_for('contracts')}}">▤ قراردادها / Contracts</a><a href="{{url_for('invoices')}}">▧ فاکتورها / Invoices</a><a href="{{url_for('suppliers')}}">♧ تأمین‌کنندگان / Suppliers</a><a href="{{url_for('inventory')}}">⌂ انبار مصالح / Inventory</a><a href="{{url_for('employees')}}">♙ کارکنان / Employees</a><a href="{{url_for('accounts')}}">▣ صندوق و بانک / Cash & Bank</a><a href="{{url_for('financial_report')}}">⌁ گزارش‌ها / Reports</a><a href="{{url_for('new_expense')}}">− هزینه جدید / Expense</a><a href="{{url_for('new_income')}}">＋ درآمد جدید / Income</a>{% if session.get('role') in ['admin','manager','accountant'] %}<a href="{{url_for('approvals')}}">✓ تأیید هزینه‌ها</a>{% endif %}{% if session.get('role') == 'admin' %}<a href="{{url_for('users')}}">⚙ کاربران</a><a href="{{url_for('activity')}}">◷ فعالیت‌ها</a>{% endif %}<a href="{{url_for('logout')}}">↪ خروج / Logout</a></div></aside><main class="company" id="company"><div class="wrap">{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="flash">{{m}}</div>{% endfor %}{% endwith %}{{body|safe}}</div></main></div><aside class="personal-drawer" id="personalDrawer" aria-hidden="true"><div class="drawer-head"><h2>حساب شخصی / Personal</h2><button class="drawer-close" onclick="togglePersonal(false)" aria-label="Close">×</button></div>{{personal|safe}}</aside>{% else %}<div class="wrap">{{body|safe}}</div>{% endif %}<script>
function togglePersonal(force){const d=document.getElementById('personalDrawer');if(!d)return;const open=typeof force==='boolean'?force:!d.classList.contains('open');d.classList.toggle('open',open);document.body.classList.toggle('personal-open',open);d.setAttribute('aria-hidden',String(!open));}
document.addEventListener('click',function(e){const s=document.querySelector('.sidebar');if(s&&s.classList.contains('open')&&!e.target.closest('.sidebar')&&!e.target.closest('.hamb'))s.classList.remove('open')});
document.addEventListener('keydown',e=>{if(e.key==='Escape')togglePersonal(false)});
</script></body></html>"""


def personal_panel():
    if not session.get("user_id"): return ""
    c=get_db(); uid=session["user_id"]
    today=date.today(); week_start=today-timedelta(days=(today.weekday()+2)%7); week_end=week_start+timedelta(days=6); month_start=today.replace(day=1)
    def total(kind,start=None,end=None):
        sql="SELECT COALESCE(SUM(amount),0) s FROM personal_transactions WHERE user_id=? AND transaction_type=?"; args=[uid,kind]
        if start: sql+=" AND transaction_date>=?"; args.append(start.isoformat())
        if end: sql+=" AND transaction_date<=?"; args.append(end.isoformat())
        return c.execute(sql,args).fetchone()["s"]
    inc=total('income'); exp=total('expense')
    periods={
      'today':(total('income',today,today),total('expense',today,today)),
      'week':(total('income',week_start,week_end),total('expense',week_start,week_end)),
      'month':(total('income',month_start,today),total('expense',month_start,today))}
    cats=c.execute("SELECT category,SUM(amount) total FROM personal_transactions WHERE user_id=? AND transaction_type='expense' GROUP BY category ORDER BY total DESC LIMIT 8",(uid,)).fetchall()
    rows=c.execute("SELECT * FROM personal_transactions WHERE user_id=? ORDER BY transaction_date DESC,id DESC LIMIT 8",(uid,)).fetchall(); c.close()
    return render_template_string("""<div class='personal-summary'><div class='card'><div class='muted'>درآمد شخصی / Income</div><div class='big'>{{inc|money}}</div><div class='period-lines'><div class='period-line'><span>امروز</span><b>{{periods.today[0]|money}}</b></div><div class='period-line'><span>این هفته</span><b>{{periods.week[0]|money}}</b></div><div class='period-line'><span>این ماه</span><b>{{periods.month[0]|money}}</b></div></div></div><div class='card'><div class='muted'>هزینه شخصی / Expenses</div><div class='big'>{{exp|money}}</div><div class='period-lines'><div class='period-line'><span>امروز</span><b>{{periods.today[1]|money}}</b></div><div class='period-line'><span>این هفته</span><b>{{periods.week[1]|money}}</b></div><div class='period-line'><span>این ماه</span><b>{{periods.month[1]|money}}</b></div></div></div><div class='card'><div class='muted'>سود خالص / Net Profit</div><div class='big'>{{(inc-exp)|money}}</div></div><div class='card'><div class='muted'>موجودی / Balance</div><div class='big'>{{(inc-exp)|money}}</div></div></div><div class='section personal-actions'><a class='btn ok' href='{{url_for("personal_new",kind="income")}}'>＋ درآمد</a><a class='btn bad' href='{{url_for("personal_new",kind="expense")}}'>− هزینه</a><a class='btn' href='{{url_for("personal_transactions")}}'>همه تراکنش‌ها</a></div><div class='card section'><h3>دسته‌های هزینه / Categories</h3>{% for x in cats %}<div style='margin:10px 0'><div style='display:flex;justify-content:space-between;font-size:11px'><span>{{x.category}}</span><span>{{x.total|money}}</span></div><div class='expense-bar'><span style='width:{{ [100,(x.total/(exp or 1))*100]|min }}%'></span></div></div>{% else %}<div class='muted'>هنوز هزینه‌ای ثبت نشده است.</div>{% endfor %}</div><div class='card section'><h3>تراکنش‌های اخیر / Recent</h3><table>{% for x in rows %}<tr><td>{{x.transaction_date}}<br><span class='muted'>{{x.description or x.category}}</span></td><td style='color:{{"#55e58a" if x.transaction_type=="income" else "#ff7782"}}'>{{x.amount|money}}</td></tr>{% else %}<tr><td class='muted'>بدون تراکنش</td></tr>{% endfor %}</table></div>""",inc=inc,exp=exp,cats=cats,rows=rows,periods=periods)
def page(title, template, **ctx):
    body = render_template_string(template, **ctx)
    return render_template_string(BASE, title=title, body=body, personal=personal_panel(), version=VERSION)


def project_list():
    c=get_db(); rows=c.execute("SELECT id,name FROM projects WHERE status='active' ORDER BY name").fetchall(); c.close(); return rows

def customer_list():
    c=get_db(); rows=c.execute("SELECT id,name FROM customers ORDER BY name").fetchall(); c.close(); return rows

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        c=get_db(); u=c.execute("SELECT * FROM users WHERE username=? AND active=1",(request.form["username"].strip(),)).fetchone(); c.close()
        if u and verify_password(request.form["password"],u["password_hash"]):
            session.clear(); session.update(user_id=u["id"],full_name=u["full_name"],role=u["role"]); log_action("login","ورود به برنامه"); return redirect(url_for("dashboard"))
        flash("نام کاربری یا رمز اشتباه است")
    return page("ورود","""<div class="login"><div class="card"><h2>ورود / Login</h2><form method="post"><div><label>نام کاربری / Username</label><input name="username" required></div><div><label>رمز عبور / Password</label><input name="password" type="password" required></div><button class="btn">ورود</button></form><p class="muted">admin / 123456</p></div></div>""")

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    c=get_db(); today=date.today(); week_start=today-timedelta(days=(today.weekday()+2)%7); week_end=week_start+timedelta(days=6); month_start=today.replace(day=1)
    def sum_table(table,date_col,status_clause='',start=None,end=None):
        sql=f"SELECT COALESCE(SUM(amount),0) s FROM {table} WHERE 1=1 {status_clause}"; args=[]
        if start: sql+=f" AND {date_col}>=?"; args.append(start.isoformat())
        if end: sql+=f" AND {date_col}<=?"; args.append(end.isoformat())
        return c.execute(sql,args).fetchone()['s']
    income=sum_table('incomes','income_date'); expense=sum_table('expenses','expense_date',"AND status='approved'")
    stats={}
    for key,a,b in [('today',today,today),('week',week_start,week_end),('month',month_start,today)]:
        i=sum_table('incomes','income_date','',a,b); e=sum_table('expenses','expense_date',"AND status='approved'",a,b); stats[key]={'income':i,'expense':e,'profit':i-e}
    receivable=c.execute("SELECT COALESCE(SUM(total-paid_amount),0) s FROM invoices WHERE status!='paid'").fetchone()["s"]
    payables=c.execute("SELECT COALESCE(SUM(balance),0) s FROM suppliers WHERE balance>0").fetchone()["s"]
    projects_count=c.execute("SELECT COUNT(*) c FROM projects WHERE status='active'").fetchone()["c"]
    customers_count=c.execute("SELECT COUNT(*) c FROM customers").fetchone()["c"]
    projs=c.execute("SELECT p.*,COALESCE((SELECT SUM(amount) FROM incomes i WHERE i.project_id=p.id),0) income,COALESCE((SELECT SUM(amount) FROM expenses e WHERE e.project_id=p.id AND e.status='approved'),0) expense FROM projects p ORDER BY p.id DESC LIMIT 5").fetchall()
    invs=c.execute("SELECT i.*,c.name customer_name FROM invoices i LEFT JOIN customers c ON c.id=i.customer_id ORDER BY i.id DESC LIMIT 5").fetchall()
    trans=c.execute("SELECT 'income' kind,i.description,i.amount,i.income_date d,p.name project FROM incomes i LEFT JOIN projects p ON p.id=i.project_id UNION ALL SELECT 'expense',e.description,e.amount,e.expense_date,p.name FROM expenses e LEFT JOIN projects p ON p.id=e.project_id WHERE e.status='approved' ORDER BY d DESC LIMIT 6").fetchall(); c.close()
    return page("داشبورد","""<div class='dashboard-title'><h1>داشبورد شرکت / Company Dashboard</h1><div class='today-chip'>{{today}} · هفته شنبه تا جمعه</div></div><div class='grid'>
    <div class='card kpi green'><div class='kpi-icon'>↗</div><div class='muted'>کل درآمد / Total Income</div><div class='big'>{{income|money}}</div><div class='period-lines'><div class='period-line'><span>امروز / Today</span><b>{{stats.today.income|money}}</b></div><div class='period-line'><span>این هفته / This Week</span><b>{{stats.week.income|money}}</b></div><div class='period-line'><span>این ماه / This Month</span><b>{{stats.month.income|money}}</b></div></div></div>
    <div class='card kpi red'><div class='kpi-icon'>↘</div><div class='muted'>کل هزینه / Total Expenses</div><div class='big'>{{expense|money}}</div><div class='period-lines'><div class='period-line'><span>امروز</span><b>{{stats.today.expense|money}}</b></div><div class='period-line'><span>این هفته</span><b>{{stats.week.expense|money}}</b></div><div class='period-line'><span>این ماه</span><b>{{stats.month.expense|money}}</b></div></div></div>
    <div class='card kpi purple'><div class='kpi-icon'>▥</div><div class='muted'>سود خالص / Net Profit</div><div class='big'>{{(income-expense)|money}}</div><div class='period-lines'><div class='period-line'><span>امروز</span><b>{{stats.today.profit|money}}</b></div><div class='period-line'><span>این هفته</span><b>{{stats.week.profit|money}}</b></div><div class='period-line'><span>این ماه</span><b>{{stats.month.profit|money}}</b></div></div></div>
    <div class='card kpi blue'><div class='kpi-icon'>▣</div><div class='muted'>مطالبات / Receivables</div><div class='big'>{{receivable|money}}</div><div class='period-lines'><div class='period-line'><span>پروژه فعال</span><b>{{projects_count}}</b></div><div class='period-line'><span>مشتریان</span><b>{{customers_count}}</b></div></div></div>
    <div class='card kpi orange'><div class='kpi-icon'>▤</div><div class='muted'>بدهی‌ها / Payables</div><div class='big'>{{payables|money}}</div><div class='period-lines'><div class='period-line'><span>وضعیت</span><b>{{'عادی' if payables==0 else 'نیاز به بررسی'}}</b></div></div></div></div>
    <div class='dash2 section'><div class='card'><div class='section-head'><h2>پروژه‌های فعال / Active Projects</h2><a href='{{url_for("projects")}}'>مشاهده همه</a></div><table><tr><th>پروژه</th><th>مشتری</th><th>پیشرفت مالی</th><th>سود فعلی</th></tr>{% for p in projs %}{% set progress=((p.expense/(p.budget or 1))*100) %}<tr><td><b>{{p.name}}</b><div class='muted'>{{p.location or ''}}</div></td><td>{{p.customer or '-'}}</td><td><div>{{'%.0f'|format([progress,100]|min)}}%</div><div class='progress'><span style='width:{{[progress,100]|min}}%'></span></div></td><td style='color:#0c9b68;font-weight:900'>{{(p.income-p.expense)|money}}</td></tr>{% else %}<tr><td colspan='4'>پروژه‌ای ثبت نشده است</td></tr>{% endfor %}</table></div><div class='card'><div class='section-head'><h2>نمودار درآمد و هزینه</h2><span class='muted'>این ماه</span></div><div class='legend'><span><i class='dot' style='background:#12a56f'></i>درآمد</span><span><i class='dot' style='background:#ef4444'></i>هزینه</span></div><div class='chart'><div class='chart-grid'></div><svg viewBox='0 0 600 200' preserveAspectRatio='none'><polyline fill='none' stroke='#12a56f' stroke-width='5' points='0,160 70,125 130,140 200,85 270,105 335,62 405,88 470,60 535,68 600,35'/><polyline fill='none' stroke='#ef4444' stroke-width='5' points='0,175 70,150 130,160 200,125 270,138 335,112 405,130 470,95 535,82 600,105'/></svg></div></div></div>
    <div class='dash2 section'><div class='card'><div class='section-head'><h2>فاکتورهای اخیر / Recent Invoices</h2><a href='{{url_for("invoices")}}'>مشاهده همه</a></div><table><tr><th>شماره</th><th>مشتری</th><th>مبلغ</th><th>وضعیت</th></tr>{% for x in invs %}<tr><td><b>{{x.invoice_no}}</b></td><td>{{x.customer_name or '-'}}</td><td>{{x.total|money}}</td><td><span class='badge {{x.status}}'>{{x.status}}</span></td></tr>{% else %}<tr><td colspan='4'>بدون فاکتور</td></tr>{% endfor %}</table></div><div class='card'><div class='section-head'><h2>تراکنش‌های اخیر / Recent Transactions</h2><span class='muted'>{{projects_count}} پروژه فعال</span></div><table><tr><th>شرح</th><th>پروژه</th><th>مبلغ</th></tr>{% for x in trans %}<tr><td>{{'↓' if x.kind=='income' else '↑'}} {{x.description}}</td><td>{{x.project or '-'}}</td><td style='font-weight:900;color:{{"#12a56f" if x.kind=="income" else "#ef4444"}}'>{{('+' if x.kind=='income' else '-') ~ (x.amount|money)}}</td></tr>{% else %}<tr><td colspan='3'>بدون تراکنش</td></tr>{% endfor %}</table></div></div>""",income=income,expense=expense,receivable=receivable,payables=payables,projects_count=projects_count,customers_count=customers_count,projs=projs,invs=invs,trans=trans,stats=stats,today=today.isoformat())
@app.route("/customers",methods=["GET","POST"])
@login_required
def customers():
    c=get_db()
    if request.method=="POST":
        c.execute("INSERT INTO customers(name,phone,email,address,rating,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",(request.form["name"],request.form.get("phone",""),request.form.get("email",""),request.form.get("address",""),request.form.get("rating","normal"),request.form.get("notes",""),session["user_id"],now())); c.commit(); log_action("create_customer",request.form["name"]); flash("مشتری ثبت شد")
    rows=c.execute("SELECT c.*,COUNT(p.id) project_count FROM customers c LEFT JOIN projects p ON p.customer_id=c.id GROUP BY c.id ORDER BY c.id DESC").fetchall(); c.close()
    return page("مشتریان","""<div class="card"><h2>مشتری جدید / New Customer</h2><form method="post"><div class="row3"><div><label>نام مشتری</label><input name="name" required></div><div><label>تلفن</label><input name="phone"></div><div><label>ایمیل</label><input name="email" type="email"></div></div><div class="row"><div><label>آدرس</label><input name="address"></div><div><label>رتبه مشتری</label><select name="rating"><option value="good">خوب / Good</option><option value="normal" selected>عادی / Normal</option><option value="bad">بدحساب / Bad</option></select></div></div><div><label>یادداشت</label><textarea name="notes"></textarea></div><button class="btn">ثبت مشتری</button></form></div><div class="card section"><h2>لیست مشتریان</h2><table><tr><th>نام</th><th>تلفن</th><th>رتبه</th><th>پروژه‌ها</th><th>یادداشت</th></tr>{% for x in rows %}<tr><td>{{x.name}}</td><td class="ltr">{{x.phone}}</td><td><span class="badge {{x.rating}}">{{x.rating}}</span></td><td>{{x.project_count}}</td><td>{{x.notes}}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/projects",methods=["GET","POST"])
@login_required
def projects():
    c=get_db()
    if request.method=="POST":
        if session["role"] not in ["admin","manager"]: flash("فقط مدیر می‌تواند پروژه ثبت کند")
        else:
            cid=request.form.get("customer_id") or None; cust=""
            if cid:
                r=c.execute("SELECT name FROM customers WHERE id=?",(cid,)).fetchone(); cust=r["name"] if r else ""
            c.execute("INSERT INTO projects(name,customer,customer_id,location,budget,status,start_date,end_date,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(request.form["name"],cust,cid,request.form.get("location",""),float(request.form.get("budget") or 0),"active",request.form.get("start_date",""),request.form.get("end_date",""),request.form.get("notes",""),session["user_id"],now())); c.commit(); log_action("create_project",request.form["name"]); flash("پروژه ثبت شد")
    rows=c.execute("""SELECT p.*,COALESCE((SELECT SUM(amount) FROM incomes i WHERE i.project_id=p.id),0) income,COALESCE((SELECT SUM(amount) FROM expenses e WHERE e.project_id=p.id AND e.status='approved'),0) expense FROM projects p ORDER BY p.id DESC""").fetchall(); customers=c.execute("SELECT id,name FROM customers ORDER BY name").fetchall(); c.close()
    return page("پروژه‌ها","""{% if session.get('role') in ['admin','manager'] %}<div class="card"><h2>پروژه جدید / New Project</h2><form method="post"><div class="row3"><div><label>نام پروژه</label><input name="name" required></div><div><label>مشتری</label><select name="customer_id"><option value="">انتخاب مشتری</option>{% for x in customers %}<option value="{{x.id}}">{{x.name}}</option>{% endfor %}</select></div><div><label>محل پروژه</label><input name="location"></div></div><div class="row3"><div><label>بودجه AED</label><input name="budget" type="number" step="0.01"></div><div><label>تاریخ شروع</label><input name="start_date" type="date"></div><div><label>تاریخ پایان</label><input name="end_date" type="date"></div></div><div><label>یادداشت</label><textarea name="notes"></textarea></div><button class="btn">ثبت پروژه</button></form></div>{% endif %}<div class="card section"><h2>لیست پروژه‌ها</h2><table><tr><th>پروژه</th><th>مشتری</th><th>بودجه</th><th>درآمد</th><th>هزینه</th><th>سود</th><th></th></tr>{% for p in rows %}<tr><td>{{p.name}}</td><td>{{p.customer or '-'}}</td><td>{{p.budget|money}}</td><td>{{p.income|money}}</td><td>{{p.expense|money}}</td><td>{{(p.income-p.expense)|money}}</td><td><a class="btn sm" href="{{url_for('project_detail',project_id=p.id)}}">جزئیات</a></td></tr>{% endfor %}</table></div>""",rows=rows,customers=customers)

@app.route("/project/<int:project_id>")
@login_required
def project_detail(project_id):
    c=get_db(); p=c.execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone()
    if not p: c.close(); flash("پروژه یافت نشد"); return redirect(url_for("projects"))
    inc=c.execute("SELECT COALESCE(SUM(amount),0) s FROM incomes WHERE project_id=?",(project_id,)).fetchone()["s"]; exp=c.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE project_id=? AND status='approved'",(project_id,)).fetchone()["s"]
    invoices=c.execute("SELECT * FROM invoices WHERE project_id=? ORDER BY id DESC",(project_id,)).fetchall(); reports=c.execute("SELECT r.*,u.full_name FROM reports r JOIN users u ON u.id=r.user_id WHERE project_id=? ORDER BY r.id DESC LIMIT 20",(project_id,)).fetchall(); c.close()
    used=(exp/p["budget"]*100) if p["budget"] else 0
    return page(p["name"],"""<div class="card"><h2>{{p.name}}</h2><div class="muted">{{p.customer or '-'}} — {{p.location or '-'}}</div></div><div class="grid section"><div class="card"><div class="muted">بودجه</div><div class="big">{{p.budget|money}}</div></div><div class="card"><div class="muted">درآمد</div><div class="big">{{inc|money}}</div></div><div class="card"><div class="muted">هزینه</div><div class="big">{{exp|money}}</div></div><div class="card"><div class="muted">سود پروژه</div><div class="big">{{(inc-exp)|money}}</div></div></div><div class="card section"><h3>مصرف بودجه: {{'%.1f'|format(used)}}%</h3><div class="progress"><span style="width:{{[used,100]|min}}%"></span></div></div><div class="card section"><h2>فاکتورها</h2><table><tr><th>شماره</th><th>تاریخ</th><th>مبلغ</th><th>پرداخت</th><th>وضعیت</th></tr>{% for x in invoices %}<tr><td>{{x.invoice_no}}</td><td>{{x.issue_date}}</td><td>{{x.total|money}}</td><td>{{x.paid_amount|money}}</td><td><span class="badge {{x.status}}">{{x.status}}</span></td></tr>{% endfor %}</table></div><div class="card section"><h2>گزارش‌های روزانه</h2><table><tr><th>کاربر</th><th>کار انجام‌شده</th><th>کارگران</th><th>زمان</th></tr>{% for x in reports %}<tr><td>{{x.full_name}}</td><td>{{x.work_done}}</td><td>{{x.workers_count}}</td><td>{{x.created_at[:10]}}</td></tr>{% endfor %}</table></div>""",p=p,inc=inc,exp=exp,used=used,invoices=invoices,reports=reports)

@app.route("/expense/new",methods=["GET","POST"])
@login_required
def new_expense():
    if request.method=="POST":
        c=get_db(); c.execute("INSERT INTO expenses(project_id,user_id,category,description,amount,status,expense_date,created_at) VALUES(?,?,?,?,?,?,?,?)",(request.form.get("project_id") or None,session["user_id"],request.form["category"],request.form["description"],float(request.form["amount"]),"pending",request.form.get("expense_date") or date.today().isoformat(),now())); c.commit(); c.close(); log_action("create_expense",request.form["description"][:80]); flash("هزینه ثبت شد و منتظر تأیید است"); return redirect(url_for("dashboard"))
    return page("ثبت هزینه","""<div class="card"><h2>ثبت هزینه / New Expense</h2><form method="post"><div class="row3"><div><label>پروژه</label><select name="project_id"><option value="">بدون پروژه</option>{% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div><div><label>دسته‌بندی</label><select name="category"><option>مصالح</option><option>دستمزد</option><option>حمل‌ونقل</option><option>ابزار</option><option>اجاره</option><option>مصارف شخصی</option><option>سایر</option></select></div><div><label>تاریخ</label><input name="expense_date" type="date" value="{{today}}"></div></div><div><label>شرح هزینه</label><textarea name="description" required></textarea></div><div><label>مبلغ AED</label><input name="amount" type="number" min="0" step="0.01" required></div><button class="btn">ثبت هزینه</button></form></div>""",projects=project_list(),today=date.today().isoformat())

@app.route("/income/new",methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def new_income():
    if request.method=="POST":
        c=get_db(); c.execute("INSERT INTO incomes(project_id,user_id,description,amount,income_date,created_at) VALUES(?,?,?,?,?,?)",(request.form.get("project_id") or None,session["user_id"],request.form["description"],float(request.form["amount"]),request.form.get("income_date") or date.today().isoformat(),now())); c.commit(); c.close(); log_action("create_income",request.form["description"][:80]); flash("درآمد ثبت شد"); return redirect(url_for("dashboard"))
    return page("ثبت درآمد","""<div class="card"><h2>ثبت درآمد / New Income</h2><form method="post"><div class="row"><div><label>پروژه</label><select name="project_id"><option value="">بدون پروژه</option>{% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div><div><label>تاریخ</label><input name="income_date" type="date" value="{{today}}"></div></div><div><label>شرح درآمد</label><textarea name="description" required></textarea></div><div><label>مبلغ AED</label><input name="amount" type="number" min="0" step="0.01" required></div><button class="btn">ثبت درآمد</button></form></div>""",projects=project_list(),today=date.today().isoformat())

@app.route("/contracts")
@login_required
def contracts():
    c=get_db(); rows=c.execute("SELECT x.*,c.name customer_name,p.name project_name FROM contracts x LEFT JOIN customers c ON c.id=x.customer_id LEFT JOIN projects p ON p.id=x.project_id ORDER BY x.id DESC").fetchall(); c.close()
    return page("قراردادها","""<div class="actions"><a class="btn" href="{{url_for('new_contract')}}">＋ قرارداد جدید / New Contract</a></div><div class="card section"><h2>قراردادها</h2><table><tr><th>شماره</th><th>عنوان</th><th>مشتری</th><th>پروژه</th><th>مبلغ</th><th>وضعیت</th></tr>{% for x in rows %}<tr><td>{{x.contract_no}}</td><td>{{x.title}}</td><td>{{x.customer_name or '-'}}</td><td>{{x.project_name or '-'}}</td><td>{{x.amount|money}}</td><td><span class="badge {{x.status}}">{{x.status}}</span></td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/contract/new",methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def new_contract():
    if request.method=="POST":
        c=get_db(); no=request.form.get("contract_no") or f"CON-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        try:
            c.execute("INSERT INTO contracts(contract_no,customer_id,project_id,title,amount,start_date,end_date,status,terms,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(no,request.form.get("customer_id") or None,request.form.get("project_id") or None,request.form["title"],float(request.form.get("amount") or 0),request.form.get("start_date",""),request.form.get("end_date",""),request.form.get("status","draft"),request.form.get("terms",""),session["user_id"],now())); c.commit(); log_action("create_contract",no); flash("قرارداد ثبت شد"); c.close(); return redirect(url_for("contracts"))
        except sqlite3.IntegrityError: flash("شماره قرارداد تکراری است"); c.close()
    return page("قرارداد جدید","""<div class="card"><h2>قرارداد جدید / New Contract</h2><form method="post"><div class="row3"><div><label>شماره قرارداد</label><input name="contract_no" placeholder="خودکار در صورت خالی بودن"></div><div><label>مشتری</label><select name="customer_id"><option value="">انتخاب</option>{% for x in customers %}<option value="{{x.id}}">{{x.name}}</option>{% endfor %}</select></div><div><label>پروژه</label><select name="project_id"><option value="">انتخاب</option>{% for x in projects %}<option value="{{x.id}}">{{x.name}}</option>{% endfor %}</select></div></div><div class="row"><div><label>عنوان قرارداد</label><input name="title" required></div><div><label>مبلغ AED</label><input name="amount" type="number" step="0.01"></div></div><div class="row3"><div><label>شروع</label><input name="start_date" type="date"></div><div><label>پایان</label><input name="end_date" type="date"></div><div><label>وضعیت</label><select name="status"><option value="draft">پیش‌نویس</option><option value="active">فعال</option><option value="completed">تکمیل</option><option value="cancelled">لغو</option></select></div></div><div><label>شرایط قرارداد</label><textarea name="terms"></textarea></div><button class="btn">ثبت قرارداد</button></form></div>""",customers=customer_list(),projects=project_list())

@app.route("/invoices")
@login_required
def invoices():
    c=get_db(); rows=c.execute("SELECT i.*,c.name customer_name,p.name project_name FROM invoices i LEFT JOIN customers c ON c.id=i.customer_id LEFT JOIN projects p ON p.id=i.project_id ORDER BY i.id DESC").fetchall(); c.close()
    return page("فاکتورها","""<div class="actions"><a class="btn" href="{{url_for('new_invoice')}}">＋ فاکتور جدید / New Invoice</a></div><div class="card section"><h2>فاکتورها</h2><table><tr><th>شماره</th><th>مشتری</th><th>پروژه</th><th>کل</th><th>پرداخت</th><th>مانده</th><th>وضعیت</th><th></th></tr>{% for x in rows %}<tr><td>{{x.invoice_no}}</td><td>{{x.customer_name or '-'}}</td><td>{{x.project_name or '-'}}</td><td>{{x.total|money}}</td><td>{{x.paid_amount|money}}</td><td>{{(x.total-x.paid_amount)|money}}</td><td><span class="badge {{x.status}}">{{x.status}}</span></td><td><a class="btn sm" href="{{url_for('invoice_view',invoice_id=x.id)}}">نمایش</a></td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/invoice/new",methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def new_invoice():
    if request.method=="POST":
        subtotal=float(request.form.get("subtotal") or 0); tax_rate=float(request.form.get("tax_rate") or 0); tax=subtotal*tax_rate/100; total=subtotal+tax; no=request.form.get("invoice_no") or f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}"; paid=float(request.form.get("paid_amount") or 0); status="paid" if paid>=total and total>0 else ("partial" if paid>0 else "unpaid")
        c=get_db()
        try:
            c.execute("INSERT INTO invoices(invoice_no,customer_id,project_id,issue_date,due_date,description,subtotal,tax_rate,tax_amount,total,paid_amount,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(no,request.form.get("customer_id") or None,request.form.get("project_id") or None,request.form.get("issue_date") or date.today().isoformat(),request.form.get("due_date",""),request.form["description"],subtotal,tax_rate,tax,total,paid,status,session["user_id"],now())); c.commit(); log_action("create_invoice",no); flash("فاکتور ثبت شد"); iid=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]; c.close(); return redirect(url_for("invoice_view",invoice_id=iid))
        except sqlite3.IntegrityError: flash("شماره فاکتور تکراری است"); c.close()
    return page("فاکتور جدید","""<div class="card"><h2>فاکتور جدید / New Invoice</h2><form method="post"><div class="row3"><div><label>شماره فاکتور</label><input name="invoice_no" placeholder="خودکار"></div><div><label>مشتری</label><select name="customer_id"><option value="">انتخاب</option>{% for x in customers %}<option value="{{x.id}}">{{x.name}}</option>{% endfor %}</select></div><div><label>پروژه</label><select name="project_id"><option value="">انتخاب</option>{% for x in projects %}<option value="{{x.id}}">{{x.name}}</option>{% endfor %}</select></div></div><div class="row"><div><label>تاریخ صدور</label><input name="issue_date" type="date" value="{{today}}"></div><div><label>سررسید</label><input name="due_date" type="date"></div></div><div><label>شرح خدمات / کالا</label><textarea name="description" required></textarea></div><div class="row3"><div><label>مبلغ قبل مالیات AED</label><input name="subtotal" type="number" min="0" step="0.01" required></div><div><label>مالیات %</label><input name="tax_rate" type="number" min="0" step="0.01" value="5"></div><div><label>پرداخت‌شده AED</label><input name="paid_amount" type="number" min="0" step="0.01" value="0"></div></div><button class="btn">صدور فاکتور</button></form></div>""",customers=customer_list(),projects=project_list(),today=date.today().isoformat())

@app.route("/invoice/<int:invoice_id>")
@login_required
def invoice_view(invoice_id):
    c=get_db(); x=c.execute("SELECT i.*,c.name customer_name,c.phone,c.address,p.name project_name FROM invoices i LEFT JOIN customers c ON c.id=i.customer_id LEFT JOIN projects p ON p.id=i.project_id WHERE i.id=?",(invoice_id,)).fetchone(); c.close()
    if not x: flash("فاکتور یافت نشد"); return redirect(url_for("invoices"))
    return page("فاکتور","""<div class="card"><div style="display:flex;justify-content:space-between;gap:12px"><div><h2>BuildAI ERP</h2><div class="muted">Invoice / فاکتور</div></div><div class="ltr"><b>{{x.invoice_no}}</b><br>{{x.issue_date}}</div></div><hr style="border:0;border-top:1px solid #eee"><div class="row"><div><h3>مشتری / Customer</h3><p>{{x.customer_name or '-'}}</p><p>{{x.phone or ''}}</p><p>{{x.address or ''}}</p></div><div><h3>پروژه / Project</h3><p>{{x.project_name or '-'}}</p><p>سررسید: {{x.due_date or '-'}}</p></div></div><div class="card" style="background:#f7f9fc;box-shadow:none"><b>{{x.description}}</b></div><table class="section"><tr><th>مبلغ پایه</th><td>{{x.subtotal|money}}</td></tr><tr><th>مالیات {{x.tax_rate}}%</th><td>{{x.tax_amount|money}}</td></tr><tr><th>جمع کل</th><td><b>{{x.total|money}}</b></td></tr><tr><th>پرداخت‌شده</th><td>{{x.paid_amount|money}}</td></tr><tr><th>مانده</th><td><b>{{(x.total-x.paid_amount)|money}}</b></td></tr></table><div class="actions section"><button class="btn gray" onclick="window.print()">چاپ / Print</button></div></div>""",x=x)

@app.route("/report/new",methods=["GET","POST"])
@login_required
def new_report():
    if request.method=="POST":
        c=get_db(); c.execute("INSERT INTO reports(project_id,user_id,work_done,workers_count,materials_used,issues,created_at) VALUES(?,?,?,?,?,?,?)",(request.form["project_id"],session["user_id"],request.form["work_done"],int(request.form.get("workers_count") or 0),request.form.get("materials_used",""),request.form.get("issues",""),now())); c.commit(); c.close(); log_action("create_report",request.form["work_done"][:80]); flash("گزارش روزانه ثبت شد"); return redirect(url_for("dashboard"))
    return page("گزارش روزانه","""<div class="card"><h2>گزارش روزانه / Daily Report</h2><form method="post"><div><label>پروژه</label><select name="project_id" required>{% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div><div><label>کارهای انجام‌شده</label><textarea name="work_done" required></textarea></div><div class="row"><div><label>تعداد کارگران</label><input name="workers_count" type="number"></div><div><label>مصالح مصرف‌شده</label><input name="materials_used"></div></div><div><label>مشکل یا تأخیر</label><textarea name="issues"></textarea></div><button class="btn">ثبت گزارش</button></form></div>""",projects=project_list())

@app.route("/approvals")
@login_required
@role_required("admin","manager","accountant")
def approvals():
    c=get_db(); rows=c.execute("SELECT e.*,u.full_name,p.name project_name FROM expenses e JOIN users u ON u.id=e.user_id LEFT JOIN projects p ON p.id=e.project_id WHERE e.status='pending' ORDER BY e.id DESC").fetchall(); c.close()
    return page("تأیید هزینه‌ها","""<div class="card"><h2>هزینه‌های منتظر تأیید</h2><table><tr><th>کارمند</th><th>پروژه</th><th>شرح</th><th>مبلغ</th><th>عملیات</th></tr>{% for x in rows %}<tr><td>{{x.full_name}}</td><td>{{x.project_name or '-'}}</td><td>{{x.description}}</td><td>{{x.amount|money}}</td><td><div class="actions"><form method="post" action="{{url_for('expense_action',expense_id=x.id,action='approve')}}"><button class="btn ok sm">تأیید</button></form><form method="post" action="{{url_for('expense_action',expense_id=x.id,action='reject')}}"><button class="btn bad sm">رد</button></form></div></td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/expense/<int:expense_id>/<action>",methods=["POST"])
@login_required
@role_required("admin","manager","accountant")
def expense_action(expense_id,action):
    status="approved" if action=="approve" else "rejected"; c=get_db(); c.execute("UPDATE expenses SET status=? WHERE id=?",(status,expense_id)); c.commit(); c.close(); log_action("expense_"+status,str(expense_id)); flash("وضعیت هزینه تغییر کرد"); return redirect(url_for("approvals"))

@app.route("/users",methods=["GET","POST"])
@login_required
@role_required("admin")
def users():
    c=get_db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO users(full_name,username,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",(request.form["full_name"],request.form["username"].strip(),hash_password(request.form["password"]),request.form["role"],now())); c.commit(); flash("کاربر ساخته شد"); log_action("create_user",request.form["username"])
        except sqlite3.IntegrityError: flash("این نام کاربری قبلاً استفاده شده است")
    rows=c.execute("SELECT * FROM users ORDER BY id DESC").fetchall(); c.close()
    return page("کاربران","""<div class="card"><h2>ساخت کاربر جدید</h2><form method="post"><div class="row"><div><label>نام کامل</label><input name="full_name" required></div><div><label>نام کاربری</label><input name="username" required></div></div><div class="row"><div><label>رمز عبور</label><input name="password" required></div><div><label>نقش</label><select name="role"><option value="employee">کارمند</option><option value="manager">مدیر پروژه</option><option value="accountant">حسابدار</option><option value="viewer">مشاهده‌گر</option></select></div></div><button class="btn">ساخت کاربر</button></form></div><div class="card section"><h2>کاربران</h2><table><tr><th>نام</th><th>نام کاربری</th><th>نقش</th></tr>{% for u in rows %}<tr><td>{{u.full_name}}</td><td>{{u.username}}</td><td>{{u.role}}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/activity")
@login_required
@role_required("admin")
def activity():
    c=get_db(); rows=c.execute("SELECT a.*,u.full_name FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").fetchall(); c.close()
    return page("فعالیت‌ها","""<div class="card"><h2>گزارش فعالیت کاربران</h2><table><tr><th>کاربر</th><th>عملیات</th><th>جزئیات</th><th>زمان</th></tr>{% for x in rows %}<tr><td>{{x.full_name or '-'}}</td><td>{{x.action}}</td><td>{{x.details}}</td><td>{{x.created_at}}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/suppliers", methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def suppliers():
    c=get_db()
    if request.method=="POST":
        c.execute("INSERT INTO suppliers(name,phone,email,address,category,balance,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(request.form["name"],request.form.get("phone",""),request.form.get("email",""),request.form.get("address",""),request.form.get("category","مصالح"),float(request.form.get("balance") or 0),request.form.get("notes",""),session["user_id"],now()))
        c.commit(); log_action("create_supplier",request.form["name"]); flash("تأمین‌کننده ثبت شد")
    rows=c.execute("SELECT * FROM suppliers ORDER BY id DESC").fetchall(); c.close()
    return page("تأمین‌کنندگان", """<div class='card'><h2>تأمین‌کننده جدید / New Supplier</h2><form method='post'><div class='row3'><div><label>نام</label><input name='name' required></div><div><label>تلفن</label><input name='phone'></div><div><label>دسته‌بندی</label><input name='category' placeholder='مصالح، ابزار، حمل'></div></div><div class='row'><div><label>ایمیل</label><input name='email' type='email'></div><div><label>مانده اولیه AED</label><input name='balance' type='number' step='0.01'></div></div><div><label>آدرس</label><input name='address'></div><div><label>یادداشت</label><textarea name='notes'></textarea></div><button class='btn'>ثبت</button></form></div><div class='card section'><h2>لیست تأمین‌کنندگان</h2><table><tr><th>نام</th><th>تلفن</th><th>دسته</th><th>مانده</th><th>یادداشت</th></tr>{% for x in rows %}<tr><td>{{x.name}}</td><td>{{x.phone}}</td><td>{{x.category}}</td><td>{{x.balance|money}}</td><td>{{x.notes}}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/employees", methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def employees():
    c=get_db()
    if request.method=="POST":
        c.execute("INSERT INTO employees(full_name,phone,job_title,salary_type,salary_rate,active,notes,created_at) VALUES(?,?,?,?,?,1,?,?)",(request.form["full_name"],request.form.get("phone",""),request.form.get("job_title",""),request.form.get("salary_type","monthly"),float(request.form.get("salary_rate") or 0),request.form.get("notes",""),now()))
        c.commit(); log_action("create_employee",request.form["full_name"]); flash("کارمند ثبت شد")
    rows=c.execute("SELECT * FROM employees ORDER BY active DESC,id DESC").fetchall(); c.close()
    return page("کارکنان", """<div class='card'><h2>کارمند جدید / New Employee</h2><form method='post'><div class='row3'><div><label>نام کامل</label><input name='full_name' required></div><div><label>تلفن</label><input name='phone'></div><div><label>سمت</label><input name='job_title'></div></div><div class='row'><div><label>نوع حقوق</label><select name='salary_type'><option value='monthly'>ماهیانه</option><option value='daily'>روزانه</option><option value='hourly'>ساعتی</option></select></div><div><label>نرخ حقوق AED</label><input name='salary_rate' type='number' step='0.01'></div></div><div><label>یادداشت</label><textarea name='notes'></textarea></div><button class='btn'>ثبت کارمند</button></form></div><div class='card section'><h2>کارکنان</h2><table><tr><th>نام</th><th>سمت</th><th>نوع</th><th>نرخ</th><th></th></tr>{% for x in rows %}<tr><td>{{x.full_name}}</td><td>{{x.job_title}}</td><td>{{x.salary_type}}</td><td>{{x.salary_rate|money}}</td><td><a class='btn sm' href='{{url_for("new_payroll",employee_id=x.id)}}'>ثبت حقوق</a></td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/payroll/new/<int:employee_id>", methods=["GET","POST"])
@login_required
@role_required("admin","accountant")
def new_payroll(employee_id):
    c=get_db(); emp=c.execute("SELECT * FROM employees WHERE id=?",(employee_id,)).fetchone()
    if not emp: c.close(); return redirect(url_for("employees"))
    if request.method=="POST":
        base=float(request.form.get("base_amount") or 0); bonus=float(request.form.get("bonus") or 0); deduction=float(request.form.get("deduction") or 0); net=base+bonus-deduction
        c.execute("INSERT INTO payroll(employee_id,period,base_amount,bonus,deduction,net_amount,paid_date,status,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(employee_id,request.form["period"],base,bonus,deduction,net,request.form.get("paid_date",""),request.form.get("status","unpaid"),request.form.get("notes",""),session["user_id"],now()))
        c.commit(); c.close(); log_action("create_payroll",emp["full_name"]); flash("حقوق ثبت شد"); return redirect(url_for("employees"))
    c.close()
    return page("ثبت حقوق", """<div class='card'><h2>ثبت حقوق {{emp.full_name}}</h2><form method='post'><div class='row3'><div><label>دوره</label><input name='period' placeholder='2026-07' required></div><div><label>حقوق پایه AED</label><input name='base_amount' type='number' step='0.01' value='{{emp.salary_rate}}'></div><div><label>پاداش AED</label><input name='bonus' type='number' step='0.01' value='0'></div></div><div class='row3'><div><label>کسری AED</label><input name='deduction' type='number' step='0.01' value='0'></div><div><label>تاریخ پرداخت</label><input name='paid_date' type='date'></div><div><label>وضعیت</label><select name='status'><option value='unpaid'>پرداخت‌نشده</option><option value='paid'>پرداخت‌شده</option></select></div></div><div><label>یادداشت</label><textarea name='notes'></textarea></div><button class='btn'>ثبت حقوق</button></form></div>""",emp=emp)

@app.route("/inventory", methods=["GET","POST"])
@login_required
def inventory():
    c=get_db()
    if request.method=="POST" and session.get("role") in ["admin","manager","accountant"]:
        c.execute("INSERT INTO inventory(item_name,unit,quantity,min_quantity,unit_cost,supplier_id,location,notes,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(request.form["item_name"],request.form.get("unit","pcs"),float(request.form.get("quantity") or 0),float(request.form.get("min_quantity") or 0),float(request.form.get("unit_cost") or 0),request.form.get("supplier_id") or None,request.form.get("location",""),request.form.get("notes",""),now()))
        c.commit(); log_action("create_inventory_item",request.form["item_name"]); flash("کالای انبار ثبت شد")
    rows=c.execute("SELECT i.*,s.name supplier_name FROM inventory i LEFT JOIN suppliers s ON s.id=i.supplier_id ORDER BY i.id DESC").fetchall(); suppliers_rows=c.execute("SELECT id,name FROM suppliers ORDER BY name").fetchall(); c.close()
    return page("انبار", """{% if session.get('role') in ['admin','manager','accountant'] %}<div class='card'><h2>کالای جدید / New Stock Item</h2><form method='post'><div class='row3'><div><label>نام کالا</label><input name='item_name' required></div><div><label>واحد</label><input name='unit' value='pcs'></div><div><label>موجودی اولیه</label><input name='quantity' type='number' step='0.01'></div></div><div class='row3'><div><label>حداقل موجودی</label><input name='min_quantity' type='number' step='0.01'></div><div><label>قیمت واحد AED</label><input name='unit_cost' type='number' step='0.01'></div><div><label>تأمین‌کننده</label><select name='supplier_id'><option value=''>-</option>{% for s in suppliers %}<option value='{{s.id}}'>{{s.name}}</option>{% endfor %}</select></div></div><div class='row'><div><label>محل انبار</label><input name='location'></div><div><label>یادداشت</label><input name='notes'></div></div><button class='btn'>ثبت کالا</button></form></div>{% endif %}<div class='card section'><h2>موجودی انبار</h2><table><tr><th>کالا</th><th>موجودی</th><th>ارزش</th><th>تأمین‌کننده</th><th>وضعیت</th><th></th></tr>{% for x in rows %}<tr><td>{{x.item_name}}</td><td>{{x.quantity}} {{x.unit}}</td><td>{{(x.quantity*x.unit_cost)|money}}</td><td>{{x.supplier_name or '-'}}</td><td>{% if x.quantity <= x.min_quantity %}<span class='badge bad'>کمبود</span>{% else %}<span class='badge good'>موجود</span>{% endif %}</td><td><a class='btn sm' href='{{url_for("inventory_move",item_id=x.id)}}'>ورود/خروج</a></td></tr>{% endfor %}</table></div>""",rows=rows,suppliers=suppliers_rows)

@app.route("/inventory/move/<int:item_id>", methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def inventory_move(item_id):
    c=get_db(); item=c.execute("SELECT * FROM inventory WHERE id=?",(item_id,)).fetchone()
    if not item: c.close(); return redirect(url_for("inventory"))
    if request.method=="POST":
        qty=float(request.form["quantity"]); typ=request.form["movement_type"]; delta=qty if typ=="in" else -qty
        if item["quantity"]+delta < 0: flash("موجودی کافی نیست"); c.close(); return redirect(url_for("inventory_move",item_id=item_id))
        c.execute("UPDATE inventory SET quantity=quantity+?,updated_at=? WHERE id=?",(delta,now(),item_id))
        c.execute("INSERT INTO inventory_movements(item_id,movement_type,quantity,project_id,note,user_id,created_at) VALUES(?,?,?,?,?,?,?)",(item_id,typ,qty,request.form.get("project_id") or None,request.form.get("note",""),session["user_id"],now()))
        c.commit(); c.close(); log_action("inventory_"+typ,item["item_name"]); flash("حرکت انبار ثبت شد"); return redirect(url_for("inventory"))
    projects=project_list(); c.close()
    return page("حرکت انبار", """<div class='card'><h2>{{item.item_name}} - موجودی {{item.quantity}} {{item.unit}}</h2><form method='post'><div class='row3'><div><label>نوع</label><select name='movement_type'><option value='in'>ورود به انبار</option><option value='out'>خروج برای پروژه</option></select></div><div><label>مقدار</label><input name='quantity' type='number' min='0.01' step='0.01' required></div><div><label>پروژه</label><select name='project_id'><option value=''>-</option>{% for p in projects %}<option value='{{p.id}}'>{{p.name}}</option>{% endfor %}</select></div></div><div><label>توضیح</label><textarea name='note'></textarea></div><button class='btn'>ثبت</button></form></div>""",item=item,projects=projects)

@app.route("/accounts", methods=["GET","POST"])
@login_required
@role_required("admin","accountant")
def accounts():
    c=get_db()
    if request.method=="POST":
        c.execute("INSERT INTO accounts(name,account_type,opening_balance,notes,active,created_at) VALUES(?,?,?,?,1,?)",(request.form["name"],request.form.get("account_type","cash"),float(request.form.get("opening_balance") or 0),request.form.get("notes",""),now())); c.commit(); flash("حساب ثبت شد")
    rows=c.execute("SELECT a.*, a.opening_balance + COALESCE(SUM(CASE WHEN t.transaction_type='in' THEN t.amount ELSE -t.amount END),0) current_balance FROM accounts a LEFT JOIN account_transactions t ON t.account_id=a.id GROUP BY a.id ORDER BY a.id").fetchall(); c.close()
    return page("صندوق و بانک", """<div class='card'><h2>حساب جدید / New Account</h2><form method='post'><div class='row3'><div><label>نام حساب</label><input name='name' required></div><div><label>نوع</label><select name='account_type'><option value='cash'>صندوق</option><option value='bank'>بانک</option><option value='card'>کارت</option></select></div><div><label>مانده اولیه AED</label><input name='opening_balance' type='number' step='0.01'></div></div><div><label>یادداشت</label><input name='notes'></div><button class='btn'>ثبت حساب</button></form></div><div class='grid section'>{% for x in rows %}<a class='card quick' href='{{url_for("account_transaction",account_id=x.id)}}'><div class='muted'>{{x.account_type}}</div><h3>{{x.name}}</h3><div class='big'>{{x.current_balance|money}}</div></a>{% endfor %}</div>""",rows=rows)

@app.route("/account/<int:account_id>/transaction", methods=["GET","POST"])
@login_required
@role_required("admin","accountant")
def account_transaction(account_id):
    c=get_db(); acc=c.execute("SELECT * FROM accounts WHERE id=?",(account_id,)).fetchone()
    if not acc: c.close(); return redirect(url_for("accounts"))
    if request.method=="POST":
        c.execute("INSERT INTO account_transactions(account_id,transaction_type,amount,reference_type,description,transaction_date,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",(account_id,request.form["transaction_type"],float(request.form["amount"]),"manual",request.form.get("description",""),request.form.get("transaction_date") or date.today().isoformat(),session["user_id"],now())); c.commit(); flash("تراکنش ثبت شد")
    rows=c.execute("SELECT * FROM account_transactions WHERE account_id=? ORDER BY transaction_date DESC,id DESC LIMIT 100",(account_id,)).fetchall(); c.close()
    return page("تراکنش حساب", """<div class='card'><h2>{{acc.name}}</h2><form method='post'><div class='row3'><div><label>نوع</label><select name='transaction_type'><option value='in'>واریز</option><option value='out'>برداشت</option></select></div><div><label>مبلغ AED</label><input name='amount' type='number' step='0.01' required></div><div><label>تاریخ</label><input name='transaction_date' type='date' value='{{today}}'></div></div><div><label>شرح</label><input name='description'></div><button class='btn'>ثبت تراکنش</button></form></div><div class='card section'><table><tr><th>تاریخ</th><th>نوع</th><th>شرح</th><th>مبلغ</th></tr>{% for x in rows %}<tr><td>{{x.transaction_date}}</td><td>{{'واریز' if x.transaction_type=='in' else 'برداشت'}}</td><td>{{x.description}}</td><td>{{x.amount|money}}</td></tr>{% endfor %}</table></div>""",acc=acc,rows=rows,today=date.today().isoformat())

@app.route("/personal/new/<kind>", methods=["GET","POST"])
@login_required
def personal_new(kind):
    if kind not in ("income","expense"): return redirect(url_for("dashboard"))
    if request.method=="POST":
        c=get_db(); c.execute("INSERT INTO personal_transactions(user_id,transaction_type,category,description,amount,transaction_date,created_at) VALUES(?,?,?,?,?,?,?)",(session["user_id"],kind,request.form["category"],request.form.get("description",""),float(request.form["amount"]),request.form.get("transaction_date") or date.today().isoformat(),now())); c.commit(); c.close(); flash("تراکنش شخصی ثبت شد"); return redirect(url_for("dashboard"))
    return page("حساب شخصی","""<div class='card'><h2>{{'درآمد شخصی جدید' if kind=='income' else 'هزینه شخصی جدید'}}</h2><form method='post'><div class='row3'><div><label>دسته‌بندی</label><select name='category'><option>حقوق</option><option>زندگی</option><option>خوراک</option><option>حمل و نقل</option><option>سلامت</option><option>سرگرمی</option><option>سایر</option></select></div><div><label>مبلغ AED</label><input name='amount' type='number' step='0.01' required></div><div><label>تاریخ</label><input name='transaction_date' type='date' value='{{today}}'></div></div><div><label>شرح</label><input name='description'></div><button class='btn'>ثبت</button></form></div>""",kind=kind,today=date.today().isoformat())

@app.route("/personal/transactions")
@login_required
def personal_transactions():
    c=get_db(); rows=c.execute("SELECT * FROM personal_transactions WHERE user_id=? ORDER BY transaction_date DESC,id DESC",(session["user_id"],)).fetchall(); c.close()
    return page("تراکنش‌های شخصی","""<div class='card'><h2>تراکنش‌های شخصی / Personal Transactions</h2><table><tr><th>تاریخ</th><th>نوع</th><th>دسته</th><th>شرح</th><th>مبلغ</th></tr>{% for x in rows %}<tr><td>{{x.transaction_date}}</td><td>{{'درآمد' if x.transaction_type=='income' else 'هزینه'}}</td><td>{{x.category}}</td><td>{{x.description}}</td><td>{{x.amount|money}}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/financial-report")
@login_required
@role_required("admin","manager","accountant")
def financial_report():
    c=get_db(); income=c.execute("SELECT COALESCE(SUM(amount),0) s FROM incomes").fetchone()["s"]; expense=c.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE status='approved'").fetchone()["s"]; payroll_total=c.execute("SELECT COALESCE(SUM(net_amount),0) s FROM payroll WHERE status='paid'").fetchone()["s"]; receivable=c.execute("SELECT COALESCE(SUM(total-paid_amount),0) s FROM invoices").fetchone()["s"]; inventory_value=c.execute("SELECT COALESCE(SUM(quantity*unit_cost),0) s FROM inventory").fetchone()["s"]
    by_category=c.execute("SELECT category,SUM(amount) total FROM expenses WHERE status='approved' GROUP BY category ORDER BY total DESC").fetchall(); by_project=c.execute("SELECT p.name,COALESCE((SELECT SUM(amount) FROM incomes i WHERE i.project_id=p.id),0) income,COALESCE((SELECT SUM(amount) FROM expenses e WHERE e.project_id=p.id AND e.status='approved'),0) expense FROM projects p ORDER BY p.id DESC").fetchall(); c.close()
    return page("گزارش مالی", """<div class='grid'><div class='card'><div class='muted'>درآمد</div><div class='big'>{{income|money}}</div></div><div class='card'><div class='muted'>هزینه پروژه‌ها</div><div class='big'>{{expense|money}}</div></div><div class='card'><div class='muted'>حقوق پرداخت‌شده</div><div class='big'>{{payroll|money}}</div></div><div class='card'><div class='muted'>سود پس از حقوق</div><div class='big'>{{(income-expense-payroll)|money}}</div></div></div><div class='grid section'><div class='card'><div class='muted'>مطالبات</div><div class='big'>{{receivable|money}}</div></div><div class='card'><div class='muted'>ارزش انبار</div><div class='big'>{{inventory_value|money}}</div></div><a class='card quick' href='{{url_for("export_finance_csv")}}'><h3>دانلود گزارش CSV</h3><div class='muted'>Export financial data</div></a></div><div class='grid3 section'><div class='card'><h2>هزینه بر اساس دسته</h2><table>{% for x in by_category %}<tr><td>{{x.category}}</td><td>{{x.total|money}}</td></tr>{% endfor %}</table></div><div class='card' style='grid-column:span 2'><h2>سود پروژه‌ها</h2><table><tr><th>پروژه</th><th>درآمد</th><th>هزینه</th><th>سود</th></tr>{% for x in by_project %}<tr><td>{{x.name}}</td><td>{{x.income|money}}</td><td>{{x.expense|money}}</td><td>{{(x.income-x.expense)|money}}</td></tr>{% endfor %}</table></div></div>""",income=income,expense=expense,payroll=payroll_total,receivable=receivable,inventory_value=inventory_value,by_category=by_category,by_project=by_project)

@app.route("/export/finance.csv")
@login_required
@role_required("admin","accountant")
def export_finance_csv():
    c=get_db(); output=io.StringIO(); w=csv.writer(output); w.writerow(["Type","Date","Project","Description","Amount AED","Status"])
    for r in c.execute("SELECT i.income_date d,p.name project,i.description,i.amount FROM incomes i LEFT JOIN projects p ON p.id=i.project_id ORDER BY i.id"):
        w.writerow(["Income",r["d"],r["project"] or "",r["description"],r["amount"],"recorded"])
    for r in c.execute("SELECT e.expense_date d,p.name project,e.description,e.amount,e.status FROM expenses e LEFT JOIN projects p ON p.id=e.project_id ORDER BY e.id"):
        w.writerow(["Expense",r["d"],r["project"] or "",r["description"],r["amount"],r["status"]])
    c.close(); data='\ufeff'+output.getvalue()
    return Response(data,mimetype="text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=buildai-finance.csv"})

init_db()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
