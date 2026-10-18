def calculate_risk(phishing_result, url_result, header_result=None):
    phishing_score = phishing_result.get("score", 0)
    url_score = url_result.get("score", 0)

    header_score = 0

    if header_result:
        header_score = header_result.get("score", 0)

    phishing_weight = 0.50
    header_weight = 0.20
    url_weight = 0.30

    phishing_contribution = round(
        phishing_score * phishing_weight
    )

    header_contribution = round(
        header_score * header_weight
    )

    url_contribution = round(
        url_score * url_weight
    )

    final_score = min(
        phishing_contribution +
        header_contribution +
        url_contribution,
        100
    )

    if final_score >= 70:
        verdict = "DANGEROUS"
        confidence = "HIGH"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
    else:
        verdict = "SAFE"
        confidence = "LOW"

    phishing_reasons = list(
        dict.fromkeys(
            phishing_result.get("reasons", [])
        )
    )

    header_reasons = []

    if header_result:
        header_reasons = list(
            dict.fromkeys(
                header_result.get("reasons", [])
            )
        )

    url_reasons = list(
        dict.fromkeys(
            url_result.get("reasons", [])
        )
    )

    return {
        "score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": list(
            dict.fromkeys(
                phishing_reasons +
                header_reasons +
                url_reasons
            )
        ),
        "findings": {
            "phishing": phishing_reasons,
            "headers": header_reasons,
            "urls": url_reasons
        },
        "breakdown": {
            "phishing": {
                "raw_score": phishing_score,
                "weight": 50,
                "contribution": phishing_contribution
            },
            "headers": {
                "raw_score": header_score,
                "weight": 20,
                "contribution": header_contribution
            },
            "urls": {
                "raw_score": url_score,
                "weight": 30,
                "contribution": url_contribution
            }
        }
    }
