from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "buildai.db"

app = Flask(__name__)
app.secret_key = "buildai-erp-v2-0-3"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        customer TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Active',
        progress INTEGER NOT NULL DEFAULT 0,
        budget REAL NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        rating INTEGER NOT NULL DEFAULT 5
    );
    """)
    if conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO projects (name, customer, status, progress, budget) VALUES (?, ?, ?, ?, ?)",
            [
                ("Villa 24", "Ahmed Al Mansoori", "Active", 82, 650000),
                ("Apartment A5", "Ali Hassan", "Active", 65, 420000),
                ("School Project", "Dubai Properties", "Completed", 100, 1200000),
            ],
        )
    if conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO customers (name, phone, rating) VALUES (?, ?, ?)",
            [
                ("Ahmed Al Mansoori", "+971 50 000 0001", 5),
                ("Ali Hassan", "+971 50 000 0002", 4),
                ("Dubai Properties", "+971 4 000 0000", 5),
            ],
        )
    conn.commit()
    conn.close()

@app.route("/")
def dashboard():
    conn = get_db()
    projects = conn.execute("SELECT * FROM projects ORDER BY id DESC LIMIT 4").fetchall()
    stats = {
        "income_today": 18250,
        "expense_today": 11820,
        "profit_today": 6430,
        "active_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE status='Active'").fetchone()[0],
        "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        "pending_invoices": 7,
    }
    conn.close()
    return render_template("dashboard.html", stats=stats, projects=projects)

@app.route("/projects", methods=["GET", "POST"])
def projects():
    conn = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        customer = request.form.get("customer", "").strip()
        status = request.form.get("status", "Active").strip()
        progress = request.form.get("progress", "0").strip()
        budget = request.form.get("budget", "0").strip()

        if not name or not customer:
            flash("Project name and customer are required.", "error")
        else:
            try:
                conn.execute(
                    "INSERT INTO projects (name, customer, status, progress, budget) VALUES (?, ?, ?, ?, ?)",
                    (name, customer, status, max(0, min(100, int(progress))), float(budget or 0)),
                )
                conn.commit()
                flash("Project added successfully.", "success")
            except ValueError:
                flash("Progress or budget is invalid.", "error")
        conn.close()
        return redirect(url_for("projects"))

    rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("projects.html", projects=rows)

@app.route("/customers", methods=["GET", "POST"])
def customers():
    conn = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        rating = request.form.get("rating", "5").strip()

        if not name:
            flash("Customer name is required.", "error")
        else:
            try:
                conn.execute(
                    "INSERT INTO customers (name, phone, rating) VALUES (?, ?, ?)",
                    (name, phone, max(1, min(5, int(rating)))),
                )
                conn.commit()
                flash("Customer added successfully.", "success")
            except ValueError:
                flash("Rating must be between 1 and 5.", "error")
        conn.close()
        return redirect(url_for("customers"))

    rows = conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("customers.html", customers=rows)

@app.route("/delete/project/<int:project_id>", methods=["POST"])
def delete_project(project_id):
    conn = get_db()
    conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Project deleted.", "success")
    return redirect(url_for("projects"))

@app.route("/delete/customer/<int:customer_id>", methods=["POST"])
def delete_customer(customer_id):
    conn = get_db()
    conn.execute("DELETE FROM customers WHERE id=?", (customer_id,))
    conn.commit()
    conn.close()
    flash("Customer deleted.", "success")
    return redirect(url_for("customers"))

init_db()

if __name__ == "__main__":
    app.run(debug=True)
