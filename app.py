
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
import sqlite3, os, hashlib, secrets
from datetime import datetime
from functools import wraps

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "buildai.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "buildai-change-this-secret")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS projects(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        customer TEXT,
        location TEXT,
        budget REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        created_by INTEGER,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS expenses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incomes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER,
        user_id INTEGER NOT NULL,
        work_done TEXT NOT NULL,
        workers_count INTEGER NOT NULL DEFAULT 0,
        materials_used TEXT,
        issues TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL
    );
    """)
    if not conn.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        conn.execute(
            "INSERT INTO users(full_name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            ("مالک / Owner", "admin", hash_password("123456"), "admin", datetime.now().isoformat(timespec="seconds"))
        )
    conn.commit()
    conn.close()

def log_action(action, details=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO activity(user_id,action,details,created_at) VALUES(?,?,?,?)",
        (session.get("user_id"), action, details, datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
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

STYLE = """
<style>
:root{--bg:#eef3f9;--card:#fff;--ink:#13203a;--muted:#71809a;--blue:#2463eb;--nav:#0e1b34;--ok:#168c5d;--bad:#c33d4d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;color:var(--ink)}
header{background:var(--nav);color:#fff;padding:18px}
header .inner{max-width:1100px;margin:auto}
.brand{font-size:23px;font-weight:900}
.nav{display:flex;gap:8px;overflow:auto;margin-top:12px}
.nav a{color:#fff;text-decoration:none;background:#ffffff18;padding:10px 12px;border-radius:12px;white-space:nowrap}
.wrap{max-width:1100px;margin:auto;padding:16px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:#fff;border-radius:18px;padding:18px;box-shadow:0 6px 22px #1d2d4d12}
.big{font-size:30px;font-weight:900;margin-top:8px}
.muted{color:var(--muted);font-size:13px}
.section{margin-top:16px}
h2{margin:0 0 14px;font-size:20px}
form{display:grid;gap:12px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
label{display:block;font-size:13px;color:var(--muted);font-weight:700;margin-bottom:6px}
input,select,textarea{width:100%;padding:13px;border:1px solid #d7dfec;border-radius:12px;font:inherit;background:white}
textarea{min-height:100px}
.btn{border:0;background:var(--blue);color:#fff;padding:12px 15px;border-radius:12px;text-decoration:none;font-weight:800;cursor:pointer;display:inline-block}
.btn.ok{background:var(--ok)} .btn.bad{background:var(--bad)} .btn.sm{padding:8px 10px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:11px;border-bottom:1px solid #e7edf6;text-align:right;vertical-align:top}
.badge{padding:5px 8px;border-radius:999px;font-size:11px;font-weight:800}
.pending{background:#fff1ce;color:#9a6100}.approved{background:#dff5e9;color:#116c49}.rejected{background:#ffe1e5;color:#9e2333}
.flash{background:#fff1ce;padding:12px;border-radius:12px;margin-bottom:12px}
.login{max-width:420px;margin:8vh auto}
.quick{display:block;text-decoration:none;color:inherit}
@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}.wrap{padding:12px}.card{padding:14px}table{font-size:12px}}
</style>
"""

BASE = """
<!doctype html><html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}} | BuildAI ERP</title>""" + STYLE + """</head><body>
{% if session.get('user_id') %}
<header><div class="inner"><div class="brand">BuildAI ERP</div>
<div class="muted" style="color:#c8d2e7">{{session.get('full_name')}} — {{session.get('role')}}</div>
<div class="nav">
<a href="{{url_for('dashboard')}}">داشبورد</a>
<a href="{{url_for('projects')}}">پروژه‌ها</a>
<a href="{{url_for('new_expense')}}">ثبت هزینه</a>
<a href="{{url_for('new_income')}}">ثبت درآمد</a>
<a href="{{url_for('new_report')}}">گزارش روزانه</a>
{% if session.get('role') in ['admin','manager','accountant'] %}<a href="{{url_for('approvals')}}">تأیید هزینه‌ها</a>{% endif %}
{% if session.get('role') == 'admin' %}<a href="{{url_for('users')}}">کاربران</a><a href="{{url_for('activity')}}">فعالیت‌ها</a>{% endif %}
<a href="{{url_for('logout')}}">خروج</a>
</div></div></header>
{% endif %}
<div class="wrap">
{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="flash">{{m}}</div>{% endfor %}{% endwith %}
{{body|safe}}</div></body></html>
"""

def page(title, template, **ctx):
    body = render_template_string(template, **ctx)
    return render_template_string(BASE, title=title, body=body)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (request.form["username"].strip(),)).fetchone()
        conn.close()
        if user and verify_password(request.form["password"], user["password_hash"]):
            session.clear()
            session.update(user_id=user["id"], full_name=user["full_name"], role=user["role"])
            log_action("login", "ورود به برنامه")
            return redirect(url_for("dashboard"))
        flash("نام کاربری یا رمز اشتباه است")
    return page("ورود", """
    <div class="login"><div class="card"><h2>ورود به برنامه</h2>
    <form method="post">
    <div><label>نام کاربری</label><input name="username" required></div>
    <div><label>رمز عبور</label><input name="password" type="password" required></div>
    <button class="btn">ورود</button></form>
    <p class="muted">ورود اولیه مدیر: admin / 123456</p>
    </div></div>""")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    income = conn.execute("SELECT COALESCE(SUM(amount),0) s FROM incomes").fetchone()["s"]
    approved = conn.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE status='approved'").fetchone()["s"]
    pending = conn.execute("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE status='pending'").fetchone()["s"]
    projects_count = conn.execute("SELECT COUNT(*) c FROM projects WHERE status='active'").fetchone()["c"]
    recent = conn.execute("""SELECT e.*,u.full_name,p.name project_name FROM expenses e
        JOIN users u ON u.id=e.user_id LEFT JOIN projects p ON p.id=e.project_id
        ORDER BY e.id DESC LIMIT 10""").fetchall()
    conn.close()
    return page("داشبورد", """
    <div class="grid">
    <div class="card"><div class="muted">کل درآمد</div><div class="big">AED {{'%.2f'|format(income)}}</div></div>
    <div class="card"><div class="muted">هزینه تأییدشده</div><div class="big">AED {{'%.2f'|format(approved)}}</div></div>
    <div class="card"><div class="muted">سود خالص</div><div class="big">AED {{'%.2f'|format(income-approved)}}</div></div>
    <div class="card"><div class="muted">پروژه فعال</div><div class="big">{{projects_count}}</div></div>
    </div>
    <div class="grid section">
    <a class="card quick" href="{{url_for('new_expense')}}"><h2>＋ ثبت هزینه</h2><div class="muted">خرید، مصالح، دستمزد و حمل</div></a>
    <a class="card quick" href="{{url_for('new_report')}}"><h2>＋ گزارش روزانه</h2><div class="muted">گزارش کارمندان پروژه</div></a>
    <a class="card quick" href="{{url_for('new_income')}}"><h2>＋ ثبت درآمد</h2><div class="muted">پرداخت مشتری</div></a>
    <div class="card"><h2>AED {{'%.2f'|format(pending)}}</h2><div class="muted">منتظر تأیید</div></div>
    </div>
    <div class="card section"><h2>آخرین هزینه‌ها</h2>
    <table><tr><th>کارمند</th><th>پروژه</th><th>شرح</th><th>مبلغ</th><th>وضعیت</th></tr>
    {% for x in recent %}<tr><td>{{x.full_name}}</td><td>{{x.project_name or '-'}}</td><td>{{x.description}}</td>
    <td>AED {{'%.2f'|format(x.amount)}}</td><td><span class="badge {{x.status}}">{{x.status}}</span></td></tr>{% endfor %}
    </table></div>""", income=income, approved=approved, pending=pending, projects_count=projects_count, recent=recent)

@app.route("/projects", methods=["GET","POST"])
@login_required
def projects():
    conn = get_db()
    if request.method == "POST":
        if session["role"] not in ["admin","manager"]:
            flash("فقط مدیر می‌تواند پروژه ثبت کند")
        else:
            conn.execute("""INSERT INTO projects(name,customer,location,budget,status,created_by,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (request.form["name"],request.form.get("customer",""),request.form.get("location",""),
                 float(request.form.get("budget") or 0),"active",session["user_id"],datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            log_action("create_project", request.form["name"])
            flash("پروژه ثبت شد")
    rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    conn.close()
    return page("پروژه‌ها", """
    {% if session.get('role') in ['admin','manager'] %}
    <div class="card"><h2>پروژه جدید</h2><form method="post">
    <div class="row"><div><label>نام پروژه</label><input name="name" required></div><div><label>نام مشتری</label><input name="customer"></div></div>
    <div class="row"><div><label>محل پروژه</label><input name="location"></div><div><label>بودجه</label><input name="budget" type="number" step="0.01"></div></div>
    <button class="btn">ثبت پروژه</button></form></div>{% endif %}
    <div class="card section"><h2>لیست پروژه‌ها</h2><table><tr><th>پروژه</th><th>مشتری</th><th>محل</th><th>بودجه</th></tr>
    {% for p in rows %}<tr><td>{{p.name}}</td><td>{{p.customer}}</td><td>{{p.location}}</td><td>AED {{'%.2f'|format(p.budget)}}</td></tr>{% endfor %}
    </table></div>""", rows=rows)

def project_list():
    conn = get_db()
    rows = conn.execute("SELECT id,name FROM projects WHERE status='active' ORDER BY name").fetchall()
    conn.close()
    return rows

@app.route("/expense/new", methods=["GET","POST"])
@login_required
def new_expense():
    if request.method == "POST":
        conn = get_db()
        conn.execute("""INSERT INTO expenses(project_id,user_id,category,description,amount,status,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (request.form.get("project_id") or None,session["user_id"],request.form["category"],
             request.form["description"],float(request.form["amount"]),"pending",datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        conn.close()
        log_action("create_expense", request.form["description"][:80])
        flash("هزینه ثبت شد و منتظر تأیید است")
        return redirect(url_for("dashboard"))
    return page("ثبت هزینه", """
    <div class="card"><h2>ثبت هزینه</h2><form method="post">
    <div class="row"><div><label>پروژه</label><select name="project_id"><option value="">بدون پروژه</option>
    {% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div>
    <div><label>دسته‌بندی</label><select name="category"><option>مصالح</option><option>دستمزد</option><option>حمل‌ونقل</option><option>ابزار</option><option>اجاره</option><option>سایر</option></select></div></div>
    <div><label>شرح هزینه</label><textarea name="description" required></textarea></div>
    <div><label>مبلغ AED</label><input name="amount" type="number" step="0.01" required></div>
    <button class="btn">ثبت هزینه</button></form></div>""", projects=project_list())

@app.route("/income/new", methods=["GET","POST"])
@login_required
@role_required("admin","manager","accountant")
def new_income():
    if request.method == "POST":
        conn = get_db()
        conn.execute("""INSERT INTO incomes(project_id,user_id,description,amount,created_at) VALUES(?,?,?,?,?)""",
            (request.form.get("project_id") or None,session["user_id"],request.form["description"],
             float(request.form["amount"]),datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        conn.close()
        log_action("create_income", request.form["description"][:80])
        flash("درآمد ثبت شد")
        return redirect(url_for("dashboard"))
    return page("ثبت درآمد", """
    <div class="card"><h2>ثبت درآمد</h2><form method="post">
    <div><label>پروژه</label><select name="project_id"><option value="">بدون پروژه</option>
    {% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div>
    <div><label>شرح درآمد</label><textarea name="description" required></textarea></div>
    <div><label>مبلغ AED</label><input name="amount" type="number" step="0.01" required></div>
    <button class="btn">ثبت درآمد</button></form></div>""", projects=project_list())

@app.route("/report/new", methods=["GET","POST"])
@login_required
def new_report():
    if request.method == "POST":
        conn = get_db()
        conn.execute("""INSERT INTO reports(project_id,user_id,work_done,workers_count,materials_used,issues,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (request.form["project_id"],session["user_id"],request.form["work_done"],
             int(request.form.get("workers_count") or 0),request.form.get("materials_used",""),
             request.form.get("issues",""),datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        conn.close()
        log_action("create_report", request.form["work_done"][:80])
        flash("گزارش روزانه ثبت شد")
        return redirect(url_for("dashboard"))
    return page("گزارش روزانه", """
    <div class="card"><h2>گزارش روزانه پروژه</h2><form method="post">
    <div><label>پروژه</label><select name="project_id" required>{% for p in projects %}<option value="{{p.id}}">{{p.name}}</option>{% endfor %}</select></div>
    <div><label>کارهای انجام‌شده</label><textarea name="work_done" required></textarea></div>
    <div class="row"><div><label>تعداد کارگران</label><input name="workers_count" type="number"></div>
    <div><label>مصالح مصرف‌شده</label><input name="materials_used"></div></div>
    <div><label>مشکل یا تأخیر</label><textarea name="issues"></textarea></div>
    <button class="btn">ثبت گزارش</button></form></div>""", projects=project_list())

@app.route("/approvals")
@login_required
@role_required("admin","manager","accountant")
def approvals():
    conn = get_db()
    rows = conn.execute("""SELECT e.*,u.full_name,p.name project_name FROM expenses e
        JOIN users u ON u.id=e.user_id LEFT JOIN projects p ON p.id=e.project_id
        WHERE e.status='pending' ORDER BY e.id DESC""").fetchall()
    conn.close()
    return page("تأیید هزینه‌ها", """
    <div class="card"><h2>هزینه‌های منتظر تأیید</h2><table>
    <tr><th>کارمند</th><th>پروژه</th><th>شرح</th><th>مبلغ</th><th>عملیات</th></tr>
    {% for x in rows %}<tr><td>{{x.full_name}}</td><td>{{x.project_name or '-'}}</td><td>{{x.description}}</td>
    <td>AED {{'%.2f'|format(x.amount)}}</td><td>
    <a class="btn ok sm" href="{{url_for('expense_action',expense_id=x.id,action='approve')}}">تأیید</a>
    <a class="btn bad sm" href="{{url_for('expense_action',expense_id=x.id,action='reject')}}">رد</a></td></tr>{% endfor %}
    </table></div>""", rows=rows)

@app.route("/expense/<int:expense_id>/<action>")
@login_required
@role_required("admin","manager","accountant")
def expense_action(expense_id, action):
    status = "approved" if action == "approve" else "rejected"
    conn = get_db()
    conn.execute("UPDATE expenses SET status=? WHERE id=?", (status, expense_id))
    conn.commit()
    conn.close()
    log_action("expense_"+status, str(expense_id))
    flash("وضعیت هزینه تغییر کرد")
    return redirect(url_for("approvals"))

@app.route("/users", methods=["GET","POST"])
@login_required
@role_required("admin")
def users():
    conn = get_db()
    if request.method == "POST":
        try:
            conn.execute("""INSERT INTO users(full_name,username,password_hash,role,active,created_at)
                VALUES(?,?,?,?,1,?)""",
                (request.form["full_name"],request.form["username"].strip(),hash_password(request.form["password"]),
                 request.form["role"],datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            flash("کاربر ساخته شد")
            log_action("create_user", request.form["username"])
        except sqlite3.IntegrityError:
            flash("این نام کاربری قبلاً استفاده شده است")
    rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return page("کاربران", """
    <div class="card"><h2>ساخت کاربر جدید</h2><form method="post">
    <div class="row"><div><label>نام کامل</label><input name="full_name" required></div>
    <div><label>نام کاربری</label><input name="username" required></div></div>
    <div class="row"><div><label>رمز عبور</label><input name="password" required></div>
    <div><label>نقش</label><select name="role"><option value="employee">کارمند</option><option value="manager">مدیر پروژه</option><option value="accountant">حسابدار</option><option value="viewer">مشاهده‌گر</option></select></div></div>
    <button class="btn">ساخت کاربر</button></form></div>
    <div class="card section"><h2>کاربران</h2><table><tr><th>نام</th><th>نام کاربری</th><th>نقش</th></tr>
    {% for u in rows %}<tr><td>{{u.full_name}}</td><td>{{u.username}}</td><td>{{u.role}}</td></tr>{% endfor %}</table></div>""", rows=rows)

@app.route("/activity")
@login_required
@role_required("admin")
def activity():
    conn = get_db()
    rows = conn.execute("""SELECT a.*,u.full_name FROM activity a LEFT JOIN users u ON u.id=a.user_id
        ORDER BY a.id DESC LIMIT 200""").fetchall()
    conn.close()
    return page("فعالیت‌ها", """
    <div class="card"><h2>گزارش فعالیت کاربران</h2><table><tr><th>کاربر</th><th>عملیات</th><th>جزئیات</th><th>زمان</th></tr>
    {% for x in rows %}<tr><td>{{x.full_name or '-'}}</td><td>{{x.action}}</td><td>{{x.details}}</td><td>{{x.created_at}}</td></tr>{% endfor %}
    </table></div>""", rows=rows)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
