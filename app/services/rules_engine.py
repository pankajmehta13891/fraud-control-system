import math
import re
from datetime import datetime, timedelta
from ..utils.text_utils import extract_urls, find_keywords, URL_RE, SHORT_LINK_RE, OTP_RE, URGENCY_RE, IMPERSONATION_RE, REFUND_RE, CALLBACK_RE, ATTACHMENT_RE, BANK_DOMAIN_RE

SHORTENER_DOMAINS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd"]
SUSPICIOUS_TLDS = [".ru", ".xyz", ".top", ".biz", ".click", ".tk"]

def sender_reputation(sender_name: str, sender_id: str, body: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    txt = f"{sender_name or ''} {sender_id or ''} {body or ''}".lower()
    if any(term in txt for term in ["rbi", "bank", "kYC", "support", "customer care", "payments app"]):
        score += 15
        reasons.append("Impersonation of financial institution/support team")
    if sender_id and any(ch.isdigit() for ch in sender_id) and len(re.sub(r'\D', '', sender_id)) >= 8:
        score += 10
        reasons.append("Sender identifier appears to use numeric spoofing")
    if "noreply" not in txt and ("otp" in txt or "verify" in txt):
        score += 10
        reasons.append("Verification-oriented sender/body combination")
    return min(score, 100), reasons

def link_risk(body: str) -> tuple[int, list[str], list[str]]:
    score = 0
    reasons = []
    urls = extract_urls(body or "")
    kw = []
    if urls:
        score += 10
        reasons.append("Message contains URL(s)")
    for url in urls:
        low = url.lower()
        if any(s in low for s in SHORTENER_DOMAINS):
            score += 30
            reasons.append("Shortened URL detected")
            kw.append(url)
        if any(tld in low for tld in SUSPICIOUS_TLDS):
            score += 10
            reasons.append("Suspicious TLD detected")
        if any(bank in low for bank in ["sbi", "hdfc", "icici", "axis", "bank", "upi", "rbi"]):
            score += 25
            reasons.append("Bank/regulated entity impersonation in link")
            kw.append(url)
    if re.search(r'www\.(?![a-z0-9-]+\.(com|in|co|org)\b)', body or "", re.I):
        score += 5
        reasons.append("Potentially malformed URL domain")
    return min(score, 100), reasons, kw

def message_rules(sender_name: str, sender_id: str, body: str, phone_or_email: str = "") -> dict:
    txt = body or ""
    score = 0
    reasons = []
    kws = []

    checks = [
        (OTP_RE, 20, "OTP/PIN/CVV request detected", ["otp", "pin", "cvv", "passcode"]),
        (URGENCY_RE, 12, "Urgency language detected", ["urgent", "immediately", "within 5 minutes", "verify now"]),
        (IMPERSONATION_RE, 18, "Impersonation of bank/RBI/payment app/KYC team", ["rbi", "bank", "kyc", "upi", "customer care"]),
        (REFUND_RE, 12, "Refund/reward/lottery/loan lure language detected", ["refund", "cashback", "reward", "lottery", "prize"]),
        (CALLBACK_RE, 8, "Call-back instruction detected", ["call", "contact", "helpline", "customer care number"]),
        (ATTACHMENT_RE, 8, "Attachment mention detected", ["attachment", "pdf", "apk", "zip"]),
    ]
    for regex, weight, reason, words in checks:
        if regex.search(txt):
            score += weight
            reasons.append(reason)
            kws.extend(words[:2])

    link_score, link_reasons, link_keywords = link_risk(txt)
    score += link_score
    reasons.extend(link_reasons)
    kws.extend(link_keywords)

    sender_score, sender_reasons = sender_reputation(sender_name, sender_id, txt)
    score += sender_score
    reasons.extend(sender_reasons)

    if "otp" in txt.lower() and any(x in txt.lower() for x in ["share", "send", "tell", "give", "confirm"]):
        score += 15
        reasons.append("OTP disclosure request phrasing")
        kws.append("share OTP")
    if any(x in txt.lower() for x in ["refund", "cashback", "reward"]) and any(x in txt.lower() for x in ["click", "tap", "login", "verify"]):
        score += 10
        reasons.append("Financial lure combined with action request")
    if len(txt) < 25 and any(x in txt.lower() for x in ["verify", "update", "urgent"]):
        score += 5
        reasons.append("Abrupt message style with action pressure")

    score = min(score, 100)
    return {
        "rule_score": score,
        "reasons": list(dict.fromkeys(reasons)),
        "keywords": list(dict.fromkeys([k for k in kws if k])),
    }

def category_from_score(score: int) -> str:
    if score < 25:
        return "Safe"
    if score < 50:
        return "Suspicious"
    if score < 75:
        return "High Risk"
    return "Critical"

def recommendation_for_category(category: str) -> str:
    return {
        "Safe": "No immediate action. Continue monitoring.",
        "Suspicious": "Review manually and keep watch.",
        "High Risk": "Contact customer and create case.",
        "Critical": "Freeze related account and escalate immediately.",
    }.get(category, "Review manually.")
