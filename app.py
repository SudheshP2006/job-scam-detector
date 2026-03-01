from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

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
    job_lower = job_text.lower()

    scam_keywords = [
        "registration",
        "otp",
        "processing",
        "fee",
        "payment",
        "send money",
        "investment",
        "pay first",
        "urgent",
        "limited time"
    ]

    matched_keywords = []

    for word in scam_keywords:
        if word in job_lower:
            matched_keywords.append(word)

    score = len(matched_keywords)
    confidence = min(score * 15, 100)

    if score >= 2:
        result = "SCAM DETECTED ⚠️"
        color = "danger"
    else:
        result = "SAFE JOB ✅"
        color = "success"

    # 🔥 CURRENT DATE & TIME
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    # ================= SAVE TO DATABASE =================
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

    if total > 0:
        avg_conf = sum(r[3] for r in rows) / total
    else:
        avg_conf = 0

    conn.close()

    return render_template("admin.html",
                           rows=rows,
                           total=total,
                           scam=scam,
                           safe=safe,
                           avg_conf=round(avg_conf, 2))

# ================= DELETE ROUTE =================
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
# ================= EDIT PAGE =================
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
# ================= UPDATE FUNCTION =================
@app.route("/update/<int:id>", methods=["POST"])
def update(id):
    if not session.get("admin"):
        return redirect(url_for("login"))

    new_text = request.form["job"]
    job_lower = new_text.lower()

    scam_keywords = [
        "registration",
        "otp",
        "processing",
        "fee",
        "payment",
        "send money",
        "investment",
        "pay first",
        "urgent",
        "limited time"
    ]

    matched = [word for word in scam_keywords if word in job_lower]

    score = len(matched)
    confidence = min(score * 15, 100)

    if score >= 2:
        result = "SCAM DETECTED ⚠️"
    else:
        result = "SAFE JOB ✅"

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
import csv
from flask import Response


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

    import csv
    from io import StringIO
    from flask import Response

    si = StringIO()
    cw = csv.writer(si, quoting=csv.QUOTE_ALL)  # 🔥 Important

    cw.writerow(["ID", "Job Text", "Result", "Confidence", "Created At"])

    for row in rows:
        clean_text = row[1].replace("\n", " ").replace("\r", " ")
        cw.writerow([row[0], clean_text, row[2], row[3], row[4]])

    output = si.getvalue()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=report.csv"}
    )
# ================= RUN =================
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)