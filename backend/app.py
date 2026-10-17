import os
import sys

project_root = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

sys.path.insert(0, project_root)

from flask import Flask, render_template, request

from analyzer.email_parser import parse_email
from analyzer.phishing_detector import detect_phishing
from analyzer.header_analyzer import analyze_headers
from analyzer.url_analyzer import analyze_urls
from analyzer.risk_engine import calculate_risk


app = Flask(
    __name__,
    template_folder="../frontend"
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    email_text = request.form.get("email", "")
    email_file = request.files.get("email_file")

    if email_file and email_file.filename:
        if not email_file.filename.lower().endswith(".eml"):
            return render_template(
                "result.html",
                result="Only .eml email files are supported."
            )

        email_text = email_file.read().decode(
            "utf-8",
            errors="replace"
        )

    if not email_text.strip():
        return render_template(
            "result.html",
            result="Please paste an email or upload an .eml file."
        )

    email_data = parse_email(email_text)

    phishing_result = detect_phishing(email_data)

    header_result = analyze_headers(
        email_data["headers"]
    )

    phishing_result["score"] = min(
        phishing_result["score"] + header_result["score"],
        100
    )

    phishing_result["reasons"].extend(
        header_result["reasons"]
    )

    url_result = analyze_urls(
        email_data["urls"]
    )

    risk_result = calculate_risk(
        phishing_result,
        url_result
    )

    risk_result["sender"] = email_data["headers"]["from"]
    risk_result["subject"] = email_data["headers"]["subject"]
    risk_result["urls"] = email_data["urls"]
    risk_result["attachments"] = email_data["attachments"]

    return render_template(
        "result.html",
        result=risk_result
    )


if __name__ == "__main__":
    app.run(debug=True)