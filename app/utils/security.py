def mask_phone(phone: str) -> str:
    if not phone:
        return ""
    digits = ''.join(ch for ch in phone if ch.isdigit())
    if len(digits) <= 4:
        return "*" * len(digits)
    return digits[:2] + "X" * max(0, len(digits)-6) + digits[-4:]

def mask_email(email: str) -> str:
    if not email or "@" not in email:
        return email or ""
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        name_masked = name[0] + "***"
    else:
        name_masked = name[:2] + "***"
    return f"{name_masked}@{domain}"

def mask_account(acct: str) -> str:
    if not acct:
        return ""
    return "XXXXXX" + acct[-4:]
