from flask import Flask, request, redirect, url_for, session, render_template_string, flash
import sqlite3, os, hashlib, secrets
from datetime import datetime, date
from functools import wraps

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "buildai.db")
VERSION = "1.1"
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
    CREATE TABLE IF NOT EXISTS activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
        details TEXT, created_at TEXT NOT NULL
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
:root{--bg:#eef3f9;--card:#fff;--ink:#13203a;--muted:#71809a;--blue:#2463eb;--nav:#0e1b34;--ok:#168c5d;--bad:#c33d4d;--gold:#c98712}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;color:var(--ink)}
header{background:var(--nav);color:#fff;padding:16px}.inner,.wrap{max-width:1180px;margin:auto}.brand{font-size:23px;font-weight:900}.version{font-size:11px;background:#ffffff20;padding:4px 8px;border-radius:20px}
.nav{display:flex;gap:7px;overflow:auto;margin-top:12px}.nav a{color:#fff;text-decoration:none;background:#ffffff18;padding:9px 11px;border-radius:11px;white-space:nowrap;font-size:13px}
.wrap{padding:16px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.card{background:#fff;border-radius:18px;padding:18px;box-shadow:0 6px 22px #1d2d4d12}.big{font-size:27px;font-weight:900;margin-top:8px}.muted{color:var(--muted);font-size:13px}.section{margin-top:16px}h2{margin:0 0 14px;font-size:20px}h3{margin:0 0 10px}
form{display:grid;gap:12px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}label{display:block;font-size:13px;color:var(--muted);font-weight:700;margin-bottom:6px}
input,select,textarea{width:100%;padding:12px;border:1px solid #d7dfec;border-radius:12px;font:inherit;background:#fff}textarea{min-height:90px}.btn{border:0;background:var(--blue);color:#fff;padding:11px 14px;border-radius:12px;text-decoration:none;font-weight:800;cursor:pointer;display:inline-block}.btn.ok{background:var(--ok)}.btn.bad{background:var(--bad)}.btn.gray{background:#64748b}.btn.sm{padding:7px 9px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:10px;border-bottom:1px solid #e7edf6;text-align:right;vertical-align:top}.badge{padding:5px 8px;border-radius:999px;font-size:11px;font-weight:800;display:inline-block}.pending,.draft,.unpaid{background:#fff1ce;color:#9a6100}.approved,.active,.paid,.good{background:#dff5e9;color:#116c49}.rejected,.cancelled,.overdue,.bad{background:#ffe1e5;color:#9e2333}.normal,.partial,.completed{background:#e8efff;color:#2654a4}
.flash{background:#fff1ce;padding:12px;border-radius:12px;margin-bottom:12px}.login{max-width:420px;margin:8vh auto}.quick{display:block;text-decoration:none;color:inherit}.actions{display:flex;gap:6px;flex-wrap:wrap}.ltr{direction:ltr;text-align:left}.progress{height:8px;background:#e7edf6;border-radius:9px;overflow:hidden}.progress span{display:block;height:100%;background:var(--blue)}
@media(max-width:850px){.grid,.grid3{grid-template-columns:1fr 1fr}.row,.row3{grid-template-columns:1fr}.wrap{padding:11px}.card{padding:14px}table{font-size:11px}.big{font-size:22px}}
@media(max-width:520px){.grid,.grid3{grid-template-columns:1fr}.hide-mobile{display:none}}
</style>"""

BASE = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}} | BuildAI ERP</title>""" + STYLE + """</head><body>
{% if session.get('user_id') %}<header><div class="inner"><div style="display:flex;justify-content:space-between"><div class="brand">BuildAI ERP <span class="version">v{{version}}</span></div><div>{{session.get('full_name')}}</div></div><div class="nav">
<a href="{{url_for('dashboard')}}">داشبورد / Dashboard</a><a href="{{url_for('projects')}}">پروژه‌ها / Projects</a><a href="{{url_for('customers')}}">مشتریان / Customers</a>
<a href="{{url_for('contracts')}}">قراردادها / Contracts</a><a href="{{url_for('invoices')}}">فاکتورها / Invoices</a><a href="{{url_for('new_expense')}}">هزینه / Expense</a><a href="{{url_for('new_income')}}">درآمد / Income</a><a href="{{url_for('new_report')}}">گزارش روزانه</a>
{% if session.get('role') in ['admin','manager','accountant'] %}<a href="{{url_for('approvals')}}">تأیید هزینه‌ها</a>{% endif %}{% if session.get('role') == 'admin' %}<a href="{{url_for('users')}}">کاربران</a><a href="{{url_for('activity')}}">فعالیت‌ها</a>{% endif %}<a href="{{url_for('logout')}}">خروج</a></div></div></header>{% endif %}
<div class="wrap">{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="flash">{{m}}</div>{% endfor %}{% endwith %}{{body|safe}}</div></body></html>"""


def page(title, template, **ctx):
    body = render_template_string(template, **ctx)
    return render_template_string(BASE, title=title, body=body, version=VERSION)


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
    c=get_db(); income=c.execute("SELECT COALESCE(SUM(amount),0) s FROM incomes").fetchone()["s"]; expense=c.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE status='approved'").fetchone()["s"]
    pending=c.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE status='pending'").fetchone()["s"]; receivable=c.execute("SELECT COALESCE(SUM(total-paid_amount),0) s FROM invoices WHERE status!='paid'").fetchone()["s"]
    projects_count=c.execute("SELECT COUNT(*) c FROM projects WHERE status='active'").fetchone()["c"]; recent=c.execute("SELECT e.*,u.full_name,p.name project_name FROM expenses e JOIN users u ON u.id=e.user_id LEFT JOIN projects p ON p.id=e.project_id ORDER BY e.id DESC LIMIT 8").fetchall()
    c.close()
    return page("داشبورد","""<div class="grid"><div class="card"><div class="muted">کل درآمد / Income</div><div class="big">{{income|money}}</div></div><div class="card"><div class="muted">هزینه تأییدشده / Expenses</div><div class="big">{{expense|money}}</div></div><div class="card"><div class="muted">سود خالص / Net Profit</div><div class="big">{{(income-expense)|money}}</div></div><div class="card"><div class="muted">مطالبات فاکتورها / Receivable</div><div class="big">{{receivable|money}}</div></div></div>
    <div class="grid section"><a class="card quick" href="{{url_for('new_expense')}}"><h3>＋ هزینه جدید</h3><div class="muted">New Expense</div></a><a class="card quick" href="{{url_for('new_invoice')}}"><h3>＋ فاکتور جدید</h3><div class="muted">New Invoice</div></a><a class="card quick" href="{{url_for('new_contract')}}"><h3>＋ قرارداد جدید</h3><div class="muted">New Contract</div></a><div class="card"><h3>{{projects_count}} پروژه فعال</h3><div class="muted">{{pending|money}} منتظر تأیید</div></div></div>
    <div class="card section"><h2>آخرین هزینه‌ها / Recent Expenses</h2><table><tr><th>کاربر</th><th>پروژه</th><th>شرح</th><th>مبلغ</th><th>وضعیت</th></tr>{% for x in recent %}<tr><td>{{x.full_name}}</td><td>{{x.project_name or '-'}}</td><td>{{x.description}}</td><td>{{x.amount|money}}</td><td><span class="badge {{x.status}}">{{x.status}}</span></td></tr>{% endfor %}</table></div>""",income=income,expense=expense,pending=pending,receivable=receivable,projects_count=projects_count,recent=recent)

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

init_db()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
