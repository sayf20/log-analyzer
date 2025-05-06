import os
from flask import Flask, render_template, request, redirect, url_for
from analyzer_utils import analyze_log  # The modular analyzer function

app = Flask(__name__)

# Make sure the logs directory exists
os.makedirs("logs", exist_ok=True)

@app.route("/", methods=["GET"])
def home():
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload_log():
    file = request.files.get("logfile")
    if file and file.filename.endswith(".log"):
        filepath = os.path.join("logs", "auth.log")
        file.save(filepath)
        return redirect(url_for("dashboard"))
    return "Invalid file. Please upload a .log file.", 400

@app.route("/dashboard")
def dashboard():
    log_path = "logs/auth.log"
    if not os.path.exists(log_path):
        return "No log file found. Please upload one first.", 400

    # Analyze the log file and get the results
    results = analyze_log(log_path)

    return render_template("dashboard.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
