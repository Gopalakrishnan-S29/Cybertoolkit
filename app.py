# ================= IMPORTS =================
from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, send_from_directory
)
import os
import smtplib
import time
import json
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_apscheduler import APScheduler
from werkzeug.utils import secure_filename

# ================= TOOL IMPORTS =================
from tools.portguardian import get_listening_ports, RISKY_PORTS
from tools.wifiguard import WiFiGuard
from tools.wifiguard_v2 import WiFiGuardV2Analyzer
from tools.stegguardian import StegGuardian
from tools.configguard import ConfigGuard
from tools.tracenet import TraceNet
from tools.metaspy import MetaSpyScanner
from tools.bannerhunter import BannerHunter
from tools.crawleye import CrawlEye
from tools.techstackprofiler import TechStackProfiler

from tools.integrity_checker import (
    create_baseline,
    check_integrity,
    save_custom_file,
    load_custom_files,
    remove_custom_file
)

# ================= FLASK APP =================
app = Flask(__name__)
app.secret_key = "supersecret"

# ================= LOG FILE CONFIG =================
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "history.json")
os.makedirs(LOG_DIR, exist_ok=True)

def load_logs():
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        # File exists but is empty or corrupted
        return []

def save_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def add_log(module, tool, target, severity, message):
    logs = load_logs()
    logs.insert(0, {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "module": module,
        "tool": tool,
        "target": target,
        "severity": severity,
        "message": message
    })
    save_logs(logs)

# ================= UPLOAD CONFIG =================
UPLOAD_FOLDER = "uploads"
ALLOWED_UPLOAD_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".pdf", ".docx"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ================= EMAIL CONFIG =================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "useforhack0629@gmail.com"
SENDER_PASSWORD = "pyascscuhmnhqcsx"
RECEIVER_EMAIL = "bharathkumarnatarajan6@gmail.com"

# ================= HOME =================
@app.route("/")
def index():
    return render_template("index.html")

# ================= CORE PAGES =================
@app.route("/system-security")
def system_security():
    return render_template("system_security.html")

@app.route("/reconnaissance")
def reconnaissance():
    return render_template("reconnaissance.html")

@app.route("/history")
def history():
    return render_template("history.html", logs=load_logs())

@app.route("/settings")
def settings():
    return render_template("settings.html")

# ================= PORT GUARDIAN =================
@app.route("/portguardian")
def portguardian():
    ports = get_listening_ports()
    risky_count = len([p for p in ports if p["risk"]])

    add_log(
        module="System Security",
        tool="PortGuardian++",
        target="localhost",
        severity="High" if risky_count else "Low",
        message=f"{risky_count} risky ports detected"
    )

    return render_template(
        "portguardian.html",
        ports=ports,
        risky_ports=RISKY_PORTS
    )

@app.route("/send_port_report", methods=["POST"])
def send_port_report():
    ports = get_listening_ports()
    risky = [p for p in ports if p["risk"]]

    if not risky:
        flash("✅ No risky ports detected.")
        return redirect(url_for("portguardian"))

    body = "⚠️ Risky Ports Report\n\n"
    for p in risky:
        body += f"{p['port']} | {p['service']} | {p['process']} (PID {p['pid']})\n"

    msg = MIMEText(body)
    msg["Subject"] = "PortGuardian++ Report"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

    add_log(
        module="System Security",
        tool="PortGuardian++",
        target="Email",
        severity="Medium",
        message="Risky ports report sent via email"
    )

    flash("📧 Report sent successfully!")
    return redirect(url_for("portguardian"))

# ================= WIFI GUARD =================
@app.route("/wifiguard", methods=["GET", "POST"])
def wifiguard():
    networks, channel_congestion, error = [], [], None

    if request.method == "POST":
        scanner = WiFiGuard()
        result = scanner.scan()

        if "error" in result:
            error = result["error"]
        else:
            networks = result["networks"]
            channel_congestion = result["channel_congestion"]

            add_log(
                module="System Security",
                tool="WiFiGuard",
                target="Wireless",
                severity="Medium" if networks else "Low",
                message=f"{len(networks)} networks detected"
            )

    return render_template(
        "wifiguard.html",
        networks=networks,
        channel_congestion=channel_congestion,
        error=error
    )

@app.route("/wifiguard/v2", methods=["GET", "POST"])
def wifiguard_v2():
    scanner = WiFiGuard()
    scan = scanner.scan()
    analyzer = WiFiGuardV2Analyzer(scan)

    add_log(
        module="System Security",
        tool="WiFiGuard v2",
        target="Wireless Analysis",
        severity="Medium",
        message="Advanced WiFi analysis completed"
    )

    return render_template(
        "wifiguard_v2.html",
        summary=analyzer.summary(),
        encryption=analyzer.encryption_distribution(),
        analysis=analyzer.risk_reasoning()
    )

# ================= STEG GUARDIAN =================
@app.route("/stegguardian", methods=["GET", "POST"])
def stegguardian():
    result, image_name = None, None

    if request.method == "POST":
        file = request.files.get("image")
        if file:
            image_name = file.filename
            path = os.path.join(UPLOAD_FOLDER, image_name)
            file.save(path)
            result = StegGuardian(path).analyze()

            add_log(
                module="System Security",
                tool="StegGuardian",
                target=image_name,
                severity="Low",
                message="Steganalysis completed"
            )

    return render_template(
        "stegguardian.html",
        result=result,
        image_name=image_name
    )

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ================= INTEGRITY CHECKER =================
@app.route("/integrity-checker", methods=["GET", "POST"])
def integrity_checker():
    message, results = None, None
    custom_files = load_custom_files()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create_baseline":
            create_baseline()
            message = "Baseline created."

        elif action == "scan":
            results, error = check_integrity()
            if error:
                message = error

            add_log(
                module="System Security",
                tool="Integrity Checker",
                target="System",
                severity="High" if results else "Low",
                message="Integrity scan completed"
            )

        elif action == "add_custom":
            save_custom_file(request.form.get("custom_file"))

        elif action == "remove_custom":
            remove_custom_file(request.form.get("file_path"))

    return render_template(
        "integrity_checker.html",
        results=results,
        message=message,
        custom_files=custom_files
    )

# ================= TRACE NET =================
@app.route("/tracenet", methods=["GET", "POST"])
def tracenet():
    if request.method == "POST":
        target = request.form.get("target")
        result = TraceNet(target).run_recon()

        add_log(
            module="Reconnaissance",
            tool="TraceNet",
            target=target,
            severity="Medium",
            message="OSINT reconnaissance completed"
        )

        return render_template(
            "tracenet.html",
            target=target,
            result=result
        )

    return render_template("tracenet.html")

# ================= META SPY =================
@app.route("/metaspy", methods=["GET", "POST"])
def metaspy():
    if request.method == "POST":
        file = request.files.get("file")
        filename = secure_filename(file.filename)

        path = os.path.join(
            UPLOAD_FOLDER,
            f"meta_{int(time.time())}_{filename}"
        )
        file.save(path)

        scanner = MetaSpyScanner()
        result = scanner.analyze_file(path)

        add_log(
            module="Reconnaissance",
            tool="MetaSpy",
            target=filename,
            severity="Low",
            message="Metadata extracted"
        )

        return render_template(
            "metaspy.html",
            target=filename,
            result=result
        )

    return render_template("metaspy.html", target=None, result=None)

# ================= BANNER HUNTER =================
@app.route("/bannerhunter", methods=["GET", "POST"])
def bannerhunter():
    if request.method == "POST":
        target = request.form.get("target")
        ports_raw = request.form.get("ports")
        ports = [int(p) for p in ports_raw.split(",")] if ports_raw else None

        hunter = BannerHunter(target, ports=ports)
        result = hunter.scan()

        add_log(
            module="Reconnaissance",
            tool="BannerHunter",
            target=target,
            severity="Medium",
            message="Service banners collected"
        )

        return render_template(
            "bannerhunter.html",
            target=target,
            ports=ports_raw,
            result=result
        )

    return render_template(
        "bannerhunter.html",
        target=None,
        ports=None,
        result=None
    )

# ================= CRAWLEYE =================
@app.route("/crawleye", methods=["GET", "POST"])
def crawleye():
    if request.method == "POST":
        target = request.form.get("target")
        depth = int(request.form.get("depth", 50))
        result = CrawlEye(target, depth).run()

        add_log(
            module="Reconnaissance",
            tool="CrawlEye",
            target=target,
            severity="Medium" if result["sensitive"] else "Low",
            message=f"{result['total_urls']} URLs discovered"
        )

        return render_template("crawleye.html", result=result)

    return render_template("crawleye.html")

# ================= TECH STACK PROFILER =================
@app.route("/techstackprofiler", methods=["GET", "POST"])
def techstackprofiler():
    result = None
    if request.method == "POST":
        target = request.form.get("target")
        result = TechStackProfiler(target).analyze()

        add_log(
            module="Reconnaissance",
            tool="TechStack Profiler",
            target=target,
            severity="Low",
            message="Tech stack identified"
        )

    return render_template("techstackprofiler.html", result=result)

# ================= CONFIG GUARD =================
@app.route("/configguard")
def configguard():
    guard = ConfigGuard()
    results = guard.analyze()

    add_log(
        module="System Security",
        tool="ConfigGuard",
        target="System Config",
        severity="Medium",
        message="Configuration analysis completed"
    )

    return render_template("configguard.html", results=results)

@app.route("/fix/<check_name>")
def fix_guide(check_name):
    try:
        return render_template(f"fix/{check_name}.html")
    except:
        return "<h2>Fix guide not available yet.</h2>", 404

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
