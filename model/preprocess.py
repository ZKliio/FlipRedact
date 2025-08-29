import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE   = re.compile(r"https?://[^\s]+")
IPV4_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# SG phones: +65 optional, 8 digits starting 3/6/8/9; broaden carefully as needed
SG_PHONE_RE = re.compile(r"(?<!\d)(?:\+65[\s-]?)?(?:[3698]\d{3}[\s-]?\d{4})(?!\d)")

# Credit card: coarse match then Luhn validation below
CC_RE    = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

# Singapore NRIC/FIN inside text (loose). Tight format is ^[STFGM]\d{7}[A-Z]$.
NRIC_RE  = re.compile(r"(?i)\b[STFGM]\d{7}[A-Z]\b")

def luhn_ok(s):
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if len(digits) < 13: return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[::-1]):
        if i % 2 == parity:
            d = d * 2
            if d > 9: d -= 9
        checksum += d
    return checksum % 10 == 0

def regex_spans(text):
    spans = []
    for pat, lab in [(EMAIL_RE,"EMAIL"), (URL_RE,"URL"), (IPV4_RE,"IP"),
                     (SG_PHONE_RE,"PHONE"), (NRIC_RE,"NATIONAL_ID")]:
        for m in pat.finditer(text):
            spans.append({"start": m.start(), "end": m.end(), "label": lab, "score": 1.0})
    for m in CC_RE.finditer(text):
        s = m.group()
        if luhn_ok(s):
            spans.append({"start": m.start(), "end": m.end(), "label": "CREDIT_CARD", "score": 1.0})
    return spans

