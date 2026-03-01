from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
import os
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ================= SCAM DETECTION FUNCTION =================
def detect_scam(job_text):
    job_lower = job_text.lower()

    scam_keywords = [
        "registration fee",
        "processing fee",
        "pay first",
        "send money",
        "investment",
        "otp",
        "bank details",
        "earn money",
        "earn 50000",
        "work from home",
        "no experience",
        "limited time",
        "urgent hiring",
        "whatsapp only",
        "telegram",
        "click link"
    ]

    matched_keywords = [word for word in scam_keywords if word in job_lower]

    score = len(matched_keywords)
    confidence = min(score * 25, 100)

    if score >= 1:
        result = "SCAM DETECTED ⚠️"
        color = "danger"
    else:
        result = "SAFE JOB ✅"
        color = "success"

    return result, color, confidence, matched_keywords


# ================= HOME =================
@app.route("/")
def home():
    return render_template("index.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "1234":
            session["admin"] = True
            return redirect(url_for("admin"))
        else:
            return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))


# ================= CHECK ROUTE =================
@app.route("/check", methods=["POST"])
def check():
    job_text = request.form["job"]

    result, color, confidence, matched_keywords = detect_scam(job_text)

    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT,
            result TEXT,
            confidence INTEGER,
            created_at TEXT
        )
    """)

    cursor.execute(
        "INSERT INTO history (text, result, confidence, created_at) VALUES (?, ?, ?, ?)",
        (job_text, result, confidence, now)
    )

    conn.commit()
    conn.close()

    return render_template("result.html",
                           result=result,
                           color=color,
                           text=job_text,
                           confidence=confidence,
                           matched=matched_keywords)


# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM history ORDER BY id DESC")
    rows = cursor.fetchall()

    total = len(rows)
    scam = len([r for r in rows if "SCAM" in r[2]])
    safe = len([r for r in rows if "SAFE" in r[2]])
    avg_conf = round(sum(r[3] for r in rows) / total, 2) if total > 0 else 0

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
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM history WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin"))


# ================= EDIT =================
@app.route("/edit/<int:id>")
def edit(id):
    if not session.get("admin"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM history WHERE id = ?", (id,))
    row = cursor.fetchone()

    conn.close()

    return render_template("edit.html", row=row)


# ================= UPDATE =================
@app.route("/update/<int:id>", methods=["POST"])
def update(id):
    if not session.get("admin"):
        return redirect(url_for("login"))

    new_text = request.form["job"]

    result, _, confidence, _ = detect_scam(new_text)

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
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history")
    rows = cursor.fetchall()
    conn.close()

    si = StringIO()
    cw = csv.writer(si, quoting=csv.QUOTE_ALL)

    cw.writerow(["ID", "Job Text", "Result", "Confidence", "Created At"])

    for row in rows:
        clean_text = row[1].replace("\n", " ").replace("\r", " ")
        cw.writerow([row[0], clean_text, row[2], row[3], row[4]])

    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=report.csv"}
    )


# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)