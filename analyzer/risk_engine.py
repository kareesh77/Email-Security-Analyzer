def calculate_risk(phishing_result, url_result):
    phishing_score = phishing_result.get("score", 0)
    url_score = url_result.get("score", 0)

    final_score = phishing_score + url_score

    if final_score >= 70:
        verdict = "DANGEROUS"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    reasons = []

    reasons.extend(
        phishing_result.get("reasons", [])
    )

    reasons.extend(
        url_result.get("reasons", [])
    )

    return {
        "score": min(final_score, 100),
        "verdict": verdict,
        "reasons": reasons
    }