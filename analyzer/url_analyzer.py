import re
from urllib.parse import urlparse, unquote


def analyze_urls(urls):
    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "bank",
        "signin",
        "authentication"
    ]

    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    for original_url in urls:
        url = unquote(original_url)
        parsed_url = urlparse(url)

        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        clean_domain = domain.split("@")[-1].split(":")[0]

        if parsed_url.scheme.lower() not in ["http", "https"]:
            score += 20
            reasons.append(
                "A link uses an unusual URL scheme"
            )

        if parsed_url.scheme.lower() != "https":
            score += 15
            reasons.append(
                "A link does not use HTTPS"
            )

        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            clean_domain
        ):
            score += 25
            reasons.append(
                "A link uses an IP address instead of a domain name"
            )

        if "@" in parsed_url.netloc:
            score += 25
            reasons.append(
                "A link hides information before the actual domain using @"
            )

        for shortened_domain in shortened_domains:
            if clean_domain == shortened_domain:
                score += 20
                reasons.append(
                    "A shortened URL was detected"
                )
                break

        for word in suspicious_words:
            if word in clean_domain or word in path:
                score += 15
                reasons.append(
                    "Suspicious words detected in a link"
                )
                break

        if len(url) > 100:
            score += 10
            reasons.append(
                "A very long URL was detected"
            )

        if clean_domain.count(".") >= 3:
            score += 10
            reasons.append(
                "A link contains multiple subdomains"
            )

        if "%" in original_url:
            score += 10
            reasons.append(
                "URL encoding was detected in a link"
            )

        if re.search(
            r"(javascript:|data:|vbscript:)",
            original_url,
            re.IGNORECASE
        ):
            score += 40
            reasons.append(
                "A potentially dangerous URL scheme was detected"
            )

    return {
        "score": min(score, 100),
        "reasons": list(dict.fromkeys(reasons))
    }