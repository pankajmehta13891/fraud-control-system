import re

URL_RE = re.compile(r'(https?://\S+|www\.\S+)', re.I)
SHORT_LINK_RE = re.compile(r'(bit\.ly|tinyurl|t\.co|goo\.gl|shorturl|rb\.gy|cutt\.ly|is\.gd)', re.I)
OTP_RE = re.compile(r'\b(otp|one time password|verification code|pin|cvv|passcode)\b', re.I)
URGENCY_RE = re.compile(r'\b(urgent|immediately|within 5 minutes|today only|suspend|verify now|action required|final warning)\b', re.I)
IMPERSONATION_RE = re.compile(r'\b(rbi|bank|branch|kyc|support|customer care|payments app|upi|card team|complaint team)\b', re.I)
REFUND_RE = re.compile(r'\b(refund|cashback|reward|lottery|prize|loan approved|winner|gift)\b', re.I)
CALLBACK_RE = re.compile(r'\b(call|contact|whatsapp|reach out|helpline|customer care number)\b', re.I)
ATTACHMENT_RE = re.compile(r'\b(attached|attachment|invoice|pdf|apk|docx|zip)\b', re.I)
SUSPICIOUS_NUMBER_RE = re.compile(r'\b(0{4,}|9{5,}|123456|987654)\b')
BANK_DOMAIN_RE = re.compile(r'\b(hdfc|sbi|icici|axis|pnb|bank|upi)\b', re.I)

def extract_urls(text: str):
    return URL_RE.findall(text or "")

def find_keywords(text: str):
    body = text or ""
    hits = []
    for name, regex in {
        "otp": OTP_RE,
        "urgency": URGENCY_RE,
        "impersonation": IMPERSONATION_RE,
        "refund": REFUND_RE,
        "callback": CALLBACK_RE,
        "attachment": ATTACHMENT_RE,
        "suspicious_number": SUSPICIOUS_NUMBER_RE,
    }.items():
        if regex.search(body):
            hits.append(name)
    return hits
