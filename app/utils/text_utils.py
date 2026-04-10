import re
from urllib.parse import urlsplit

# Broad URL matching:
# - standard URLs: https://..., http://..., www....
# - naked domains with common/public TLDs
# - keeps paths/query strings
URL_RE = re.compile(
    r"""(?ix)
    (?<!@)
    \b(
        (?:
            https?://
            | hxxps?://
            | www\.
        )
        [^\s<>()\[\]{}"']+
        |
        (?:
            (?:[a-z0-9-]+\.)+
            (?:com|in|net|org|co|io|ai|app|biz|fit|xyz|top|click|shop|site|online|info|live|bank|finance|loan|club|pro|ru|tk|cc|me)
        )
        (?:/[^\s<>()\[\]{}"']*)?
    )
    """
)

SHORT_LINK_RE = re.compile(
    r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|shorturl\.at|rb\.gy|cutt\.ly|is\.gd|rebrand\.ly)\b',
    re.I,
)

OTP_RE = re.compile(
    r'\b(?:otp|one time password|verification code|pin|cvv|passcode|security code)\b',
    re.I,
)

URGENCY_RE = re.compile(
    r'\b(?:urgent|immediately|within 5 minutes|today only|suspend|verify now|action required|final warning|last chance|limited time)\b',
    re.I,
)

IMPERSONATION_RE = re.compile(
    r'\b(?:rbi|bank|branch|kyc|support|customer care|payments app|upi|card team|complaint team|wallet support|account team)\b',
    re.I,
)

REFUND_RE = re.compile(
    r'\b(?:refund|cashback|reward|lottery|prize|loan approved|winner|gift|voucher|cash prize)\b',
    re.I,
)

CALLBACK_RE = re.compile(
    r'\b(?:call|contact|whatsapp|reach out|helpline|customer care number|support number)\b',
    re.I,
)

ATTACHMENT_RE = re.compile(
    r'\b(?:attached|attachment|invoice|pdf|apk|docx|zip|file)\b',
    re.I,
)

SUSPICIOUS_NUMBER_RE = re.compile(r'\b(?:0{4,}|9{5,}|123456|987654)\b')
BANK_DOMAIN_RE = re.compile(r'\b(?:hdfc|sbi|icici|axis|pnb|bank|upi|rbi)\b', re.I)

# Extra signals for scammy promotion / investment lure text.
FINANCIAL_PROMO_RE = re.compile(
    r'\b(?:daily market notes|market tips|stock tips|trading signal|investment advice|join channel|telegram channel|guaranteed returns|sure profit|double your money|free alert|profit signal)\b',
    re.I,
)

TRAILING_PUNCT_RE = re.compile(r'[)\].,!?;:]+$')


def _clean_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    url = TRAILING_PUNCT_RE.sub("", url)
    return url


def extract_urls(text: str):
    """
    Return a deduplicated list of URL-like strings.
    """
    body = text or ""
    matches = [_clean_url(m) for m in URL_RE.findall(body)]
    out = []
    seen = set()
    for url in matches:
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def _host_and_path(url: str):
    """
    Parse a URL-like string even when it lacks a scheme.
    """
    if not url:
        return "", ""
    raw = url.strip()
    if raw.startswith("www."):
        raw = "https://" + raw
    elif not raw.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        raw = "https://" + raw
    parts = urlsplit(raw.replace("hxxp://", "http://").replace("hxxps://", "https://"))
    host = parts.netloc.lower()
    path = (parts.path or "").lower()
    if parts.query:
        path += "?" + parts.query.lower()
    return host, path


def suspicious_url_indicators(url: str):
    """
    Return (score, reasons, keywords) for URL-level risk signals.
    """
    score = 0
    reasons = []
    keywords = []

    host, path = _host_and_path(url)
    full = f"{host}{path}"

    if not host:
        return 0, reasons, keywords

    if SHORT_LINK_RE.search(host):
        score += 30
        reasons.append("Shortened URL detected")
        keywords.append(host)

    suspicious_tlds = (".ru", ".xyz", ".top", ".biz", ".click", ".tk", ".fit", ".buzz", ".loan")
    if any(host.endswith(tld) for tld in suspicious_tlds):
        score += 12
        reasons.append("Suspicious TLD detected")
        keywords.append(host)

    if "xn--" in host:
        score += 15
        reasons.append("Punycode domain detected")
        keywords.append(host)

    if re.search(r'(?:^|/)[a-z0-9]{8,}(?:/|$)', path):
        score += 8
        reasons.append("Random-looking path token detected")

    if re.search(r'[a-z]{2,}\d{2,}|\d{2,}[a-z]{2,}', path):
        score += 6
        reasons.append("Mixed alphanumeric token in URL path")

    if re.search(r'\b(?:bank|upi|rbi|kyc|refund|otp|verify|secure|login|support)\b', full, re.I):
        score += 20
        reasons.append("Financial impersonation or verification lure in URL")
        keywords.append(url)

    if len(path) >= 20 and sum(ch.isdigit() for ch in path) >= 3:
        score += 5
        reasons.append("Long tokenized URL path")

    return min(score, 100), list(dict.fromkeys(reasons)), list(dict.fromkeys([k for k in keywords if k]))


def find_keywords(text: str):
    body = text or ""
    hits = []
    patterns = {
        "otp": OTP_RE,
        "urgency": URGENCY_RE,
        "impersonation": IMPERSONATION_RE,
        "refund": REFUND_RE,
        "callback": CALLBACK_RE,
        "attachment": ATTACHMENT_RE,
        "suspicious_number": SUSPICIOUS_NUMBER_RE,
        "financial_promo": FINANCIAL_PROMO_RE,
        "bank_terms": BANK_DOMAIN_RE,
    }
    for name, regex in patterns.items():
        if regex.search(body):
            hits.append(name)

    urls = extract_urls(body)
    if urls:
        hits.append("url_present")
        for url in urls:
            score, reasons, _ = suspicious_url_indicators(url)
            if score > 0:
                hits.append("suspicious_url")
                if reasons:
                    hits.append(reasons[0].lower().replace(" ", "_"))

    return list(dict.fromkeys(hits))