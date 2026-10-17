import re
from email import policy
from email.parser import Parser
from html import unescape


def extract_urls(text):
    if not text:
        return []

    text = unescape(text)

    urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text,
        re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def parse_email(email_text):
    message = Parser(
        policy=policy.default
    ).parsestr(email_text)

    headers = {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "cc": message.get("Cc", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", "")
    }

    plain_body = ""
    html_body = ""
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename:
                attachments.append(filename)

            if content_type == "text/plain":
                try:
                    plain_body += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_body += part.get_content()
                except Exception:
                    pass
    else:
        content_type = message.get_content_type()

        if content_type == "text/html":
            try:
                html_body = message.get_content()
            except Exception:
                html_body = ""
        else:
            try:
                plain_body = message.get_content()
            except Exception:
                plain_body = ""

    body = plain_body

    if html_body:
        body += "\n" + html_body

    urls = extract_urls(body)

    html_urls = re.findall(
        r"""(?:href|src)\s*=\s*["'](https?://[^"']+)["']""",
        html_body,
        re.IGNORECASE
    )

    for url in html_urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in urls:
            urls.append(url)

    return {
        "headers": headers,
        "body": body,
        "plain_body": plain_body,
        "html_body": html_body,
        "urls": urls,
        "attachments": list(dict.fromkeys(attachments))
    }
