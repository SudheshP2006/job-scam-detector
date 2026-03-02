from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
import os
import csv
from io import StringIO
import joblib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ================= LOAD ML MODEL =================
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ================= INIT DATABASE =================
def init_db():
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    # HISTORY TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            text TEXT,
            result TEXT,
            confidence REAL,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= ML SCAM DETECTION =================
def detect_scam(job_text):
    vector = vectorizer.transform([job_text])
    prediction = model.predict(vector)[0]
    probability = model.predict_proba(vector)[0][1]

    confidence = round(probability * 100, 2)

    if prediction == 1:
        result = "SCAM DETECTED ⚠️"
        color = "danger"
    else:
        result = "SAFE JOB ✅"
        color = "success"

    return result, color, confidence

# ================= HOME =================
@app.route("/")
def home():
    return render_template("index.html")

# ================= USER REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("history.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except:
            conn.close()
            return "Username or Email already exists!"

    return render_template("register.html")

# ================= USER LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")

# ================= ADMIN LOGIN =================
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == "sudhesh" and password == "260206":
            session["admin"] = True
            return redirect(url_for("admin"))

        return "Invalid Admin Login"

    return render_template("admin_login.html")

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ================= CHECK ROUTE =================
@app.route("/check", methods=["POST"])
def check():
    job_text = request.form["job"]

    result, color, confidence = detect_scam(job_text)
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    user_id = session.get("user_id")

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO history (user_id, text, result, confidence, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, job_text, result, confidence, now)
    )

    conn.commit()
    conn.close()

    return render_template("result.html",
                           result=result,
                           color=color,
                           text=job_text,
                           confidence=confidence)

# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT history.id, users.username, history.text,
               history.result, history.confidence, history.created_at
        FROM history
        LEFT JOIN users ON history.user_id = users.id
        ORDER BY history.id DESC
    """)
    rows = cursor.fetchall()

    total = len(rows)
    scam = len([r for r in rows if "SCAM" in r[3]])
    safe = len([r for r in rows if "SAFE" in r[3]])
    avg_conf = round(sum(r[4] for r in rows) / total, 2) if total > 0 else 0

    conn.close()

    return render_template("admin.html",
                           rows=rows,
                           total=total,
                           scam=scam,
                           safe=safe,
                           avg_conf=avg_conf)

# ================= DELETE =================
@app.route("/delete/<int:id>")
def delete(id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

# ================= UPDATE =================
@app.route("/update/<int:id>", methods=["POST"])
def update(id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    new_text = request.form["job"]
    result, _, confidence = detect_scam(new_text)

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE history
        SET text = ?, result = ?, confidence = ?
        WHERE id = ?
    """, (new_text, result, confidence, id))

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

# ================= EXPORT CSV =================
@app.route("/export")
def export_csv():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history")
    rows = cursor.fetchall()
    conn.close()

    si = StringIO()
    cw = csv.writer(si, quoting=csv.QUOTE_ALL)

    cw.writerow(["ID", "User ID", "Job Text", "Result", "Confidence", "Created At"])

    for row in rows:
        clean_text = row[2].replace("\n", " ").replace("\r", " ")
        cw.writerow([row[0], row[1], clean_text, row[3], row[4], row[5]])

    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=report.csv"}
    )

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)