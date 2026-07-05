from flask import Flask, render_template, request, send_file
import pandas as pd
import os

from parser import LogParser
from detector import ThreatDetector

app = Flask(__name__)
print("App root:", app.root_path)
print("Template folder:", app.template_folder)

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/", methods=["GET", "POST"])
def home():

    filename = "servers.log"

    if request.method == "POST":

        uploaded_file = request.files.get("logfile")

        if uploaded_file and uploaded_file.filename != "":

            filename = uploaded_file.filename

            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            uploaded_file.save(save_path)

    parser = LogParser(os.path.join("logs", filename))
    logs = parser.parse()

    detector = ThreatDetector(logs)

    failed = detector.failed_logins()
    brute = detector.brute_force()
    top_attackers = detector.top_attackers()

    success = len([log for log in logs if log["status"] == 200])
    failed_count = len(failed)

    return render_template(
        "index.html",
        logs=logs,
        failed=failed,
        brute=brute,
        top_attackers=top_attackers,
        total_logs=len(logs),
        total_failed=failed_count,
        suspicious_ips=len(brute),
        success=success,
        failed_count=failed_count
    )
@app.route("/download_csv")
def download_csv():

    parser = LogParser("logs/servers.log")
    logs = parser.parse()

    detector = ThreatDetector(logs)
    failed = detector.failed_logins()

    df = pd.DataFrame(failed)

    filename = "failed_logins.csv"

    df.to_csv(filename, index=False)

    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)