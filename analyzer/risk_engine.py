def calculate_risk(phishing_result, url_result):
    phishing_score = phishing_result.get("score", 0)
    url_score = url_result.get("score", 0)

    final_score = min(
        round(
            (phishing_score * 0.6) +
            (url_score * 0.4)
        ),
        100
    )

    if final_score >= 60:
        verdict = "DANGEROUS"
        confidence = "HIGH"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
    else:
        verdict = "SAFE"
        confidence = "LOW"

    reasons = []

    reasons.extend(
        phishing_result.get("reasons", [])
    )

    reasons.extend(
        url_result.get("reasons", [])
    )

    unique_reasons = list(
        dict.fromkeys(reasons)
    )

    return {
        "score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": unique_reasons
    }
