from flask import Flask, request, render_template, redirect
import joblib
import sqlite3
from datetime import datetime
app = Flask(__name__)

model = joblib.load("model/phishing_model.pkl")

@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    risk_score = 0
    threats = []
    risk_color = "success"

    if request.method == "POST":

        email_text = request.form["email"]

        email_lower = email_text.lower()

        if "password" in email_lower:
            risk_score += 20
            threats.append("Password keyword detected")

        if "verify" in email_lower:
            risk_score += 15
            threats.append("Verification request detected")

        if "urgent" in email_lower:
            risk_score += 15
            threats.append("Urgent language detected")

        if "click here" in email_lower:
            risk_score += 20
            threats.append("Suspicious action request")

        if "http" in email_lower or "www" in email_lower:
            risk_score += 30
            threats.append("Link detected")
            
        if risk_score <= 30:
            risk_color = "success"

        elif risk_score <= 60:
            risk_color = "warning"

        else:
            risk_color = "danger"

        prediction = model.predict([email_text])

        if prediction[0] == 1 or risk_score >= 50:
            result = "⚠️ Phishing Email Detected"
        else:
            result = "✅ Safe Email"

        current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        conn = sqlite3.connect("database/history.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO scans (email_text, result, scan_time) VALUES (?, ?, ?)",
            (email_text, result, current_time)
        )

        conn.commit()
        conn.close()

    return render_template(
        "index.html",
        result=result,
        risk_score=risk_score,
        threats=threats,
        risk_color=risk_color
    )


@app.route("/history")
def history():
    conn = sqlite3.connect("database/history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()
    return render_template(
        "history.html",
        data=data
    )

@app.route("/clear_history")
def clear_history():

    conn = sqlite3.connect("database/history.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scans")

    conn.commit()
    conn.close()

    return redirect("/history")

if __name__ == "__main__":
    app.run(debug=True)