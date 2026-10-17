import re


def extract_domain(value):
    if not value:
        return ""

    match = re.search(
        r"@([A-Za-z0-9.-]+)",
        value
    )

    if not match:
        return ""

    return match.group(1).lower().strip(".")


def analyze_headers(headers):
    score = 0
    reasons = []

    sender = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    if sender and not sender_domain:
        score += 15
        reasons.append(
            "Sender address could not be reliably identified"
        )

    if reply_domain and sender_domain:
        if reply_domain != sender_domain:
            score += 20
            reasons.append(
                "Reply-To domain differs from the sender domain"
            )

    if return_domain and sender_domain:
        if return_domain != sender_domain:
            score += 15
            reasons.append(
                "Return-Path domain differs from the sender domain"
            )

    if sender_domain:
        suspicious_patterns = [
            r"\d{5,}",
            r"^[a-z0-9-]+-security",
            r"^[a-z0-9-]+-support",
            r"verify",
            r"account",
            r"secure"
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, sender_domain):
                score += 10
                reasons.append(
                    "Sender domain contains suspicious naming patterns"
                )
                break

        brand_patterns = [
            (r"paypa[l1]", "paypal"),
            (r"micros[o0]ft", "microsoft"),
            (r"g[o0][o0]gle", "google"),
            (r"app[l1]e", "apple"),
            (r"amaz[o0]n", "amazon"),
            (r"faceb[o0][o0]k", "facebook")
        ]

        for pattern, brand in brand_patterns:
            if re.search(pattern, sender_domain):
                score += 20
                reasons.append(
                    "Sender domain may imitate a well-known brand"
                )
                break

    return {
        "score": min(score, 100),
        "reasons": list(dict.fromkeys(reasons))
    }
