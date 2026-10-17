import re


def detect_phishing(email_data):
    score = 0
    reasons = []

    headers = email_data["headers"]
    sender = headers["from"].lower()
    subject = headers["subject"].lower()
    body = email_data["body"].lower()
    attachments = email_data.get("attachments", [])

    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "account suspended",
        "account will be closed",
        "verify your account",
        "confirm your account"
    ]

    sensitive_words = [
        "password",
        "otp",
        "pin",
        "credit card",
        "bank account",
        "login",
        "verify"
    ]

    phishing_phrases = [
        "click here to verify",
        "click below to continue",
        "your account has been compromised",
        "your account will be locked",
        "confirm your identity",
        "update your payment information",
        "failure to respond",
        "failure to verify"
    ]

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1",
        ".jar"
    ]

    for word in urgent_words:
        if word in subject or word in body:
            score += 10
            reasons.append("Urgent or threatening language detected")
            break

    for word in sensitive_words:
        if word in body:
            score += 15
            reasons.append("Sensitive information request detected")
            break

    if re.search(r"\b(click here|click the link|open the link)\b", body):
        score += 15
        reasons.append("Email asks the user to click a link")

    for phrase in phishing_phrases:
        if phrase in body:
            score += 15
            reasons.append("Common phishing language detected")
            break

    if sender:
        suspicious_sender_words = [
            "support",
            "security",
            "admin",
            "verify",
            "account"
        ]

        for word in suspicious_sender_words:
            if word in sender:
                score += 10
                reasons.append(
                    "Sender address contains a security-related identity"
                )
                break

    if email_data.get("urls"):
        score += 20
        reasons.append("Links detected in email")

    if attachments:
        score += 10
        reasons.append("Email contains file attachments")

    for attachment in attachments:
        attachment_lower = attachment.lower()

        for extension in dangerous_extensions:
            if attachment_lower.endswith(extension):
                score += 25
                reasons.append(
                    "Potentially dangerous attachment detected"
                )
                break

    return {
        "score": min(score, 100),
        "reasons": list(dict.fromkeys(reasons))
    }
