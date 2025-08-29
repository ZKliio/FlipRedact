# PII detection and redaction model combining regex and ML-based NER

import re

# Define regex patterns for various PII types
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE   = re.compile(r"https?://[^\s]+")
IPV4_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# SG phones: +65 optional, 8 digits starting 3/6/8/9; broaden carefully as needed
SG_PHONE_RE = re.compile(r"(?<!\d)(?:\+65[\s-]?)?(?:[3698]\d{3}[\s-]?\d{4})(?!\d)")

# Credit card: coarse match then Luhn validation below
CC_RE    = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

# Singapore NRIC/FIN inside text (loose). Tight format is ^[STFGM]\d{7}[A-Z]$.
NRIC_RE  = re.compile(r"(?i)\b[STFGM]\d{7}[A-Z]\b")

# Luhn algorithm to validate credit card numbers
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

# Extract PII spans using regex patterns
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

# ML-based NER using HuggingFace transformers
from transformers import AutoTokenizer, AutoModelForTokenClassification
import torch

MODEL = "dslim/bert-base-NER"  # good starting checkpoint; swap with your fine-tuned DistilBERT later
tok = AutoTokenizer.from_pretrained(MODEL, use_fast=True)
ner = AutoModelForTokenClassification.from_pretrained(MODEL).eval()
id2label = ner.config.id2label

def ml_spans(text, threshold=0.6):
    enc = tok(text, return_offsets_mapping=True, return_tensors="pt", truncation=True)
    offsets = enc.pop("offset_mapping")[0].tolist()
    with torch.no_grad():
        logits = ner(**enc).logits[0]
    probs = torch.softmax(logits, dim=-1)
    spans, cur = [], None
    for i, (st, en) in enumerate(offsets):
        if en == 0: 
            continue
        label_id = int(probs[i].argmax())
        label = id2label[label_id]
        score = float(probs[i, label_id])
        
        pref, ent = (label.split("-") + [""])[:2]
        if score < threshold or label == "O":      # This is placed after instead of before the B check to avoid dropping low-confidence B tags
            if cur: spans.append(cur); cur = None
            continue

        if pref == "B" or cur is None or (cur and ent != cur["label"]): # cur is None added to handle first entity case
            if cur: spans.append(cur)
            cur = {"start": st, "end": en, "label": ent, "score": score}
        else:
            cur["end"] = en
            cur["score"] = max(cur["score"], score)
    if cur: spans.append(cur)
    # Map general NER tags to your PII taxonomy
    for s in spans:
        if s["label"] == "PER": s["label"] = "PERSON"
        if s["label"] == "LOC": s["label"] = "GPE"
        if s["label"] == "MISC": s["label"] = "ORG"
    return spans


# Merge overlapping/contained spans, keeping the longest or highest-confidence
def merge_spans(spans):
    spans = sorted(spans, key=lambda s: (s["start"], -s["end"]))
    out = []
    for s in spans:
        if out and s["start"] <= out[-1]["end"]:
            if (s["end"]-s["start"] > out[-1]["end"]-out[-1]["start"]) or (s["score"] > out[-1]["score"]):
                out[-1] = s
        else:
            out.append(s)
    return out

POLICY = {
    "EMAIL":"[EMAIL]","PHONE":"[PHONE]","CREDIT_CARD":"[CARD]","IP":"[IP]","URL":"[URL]",
    "PERSON":"[NAME]","ORG":"[ORG]","GPE":"[LOCATION]","ADDRESS":"[ADDRESS]","NATIONAL_ID":"[ID]"
}

def redact(text, extra_policy=None):
    policy = {**POLICY, **(extra_policy or {})}
    spans = merge_spans(regex_spans(text) + ml_spans(text))
    res, last = [], 0
    for s in spans:
        res.append(text[last:s["start"]])
        res.append(policy.get(s["label"], "[REDACTED]"))
        last = s["end"]
    res.append(text[last:])
    return "".join(res)

# print(redact("I’m Alex Tan, NRIC S1234567D, phone +65 9123 4567, email alex@ex.com."))

# --- quick test harness for the PII filter ---
# if __name__ == "__main__":
#     while True:
#         text = input("\nEnter text to redact (or 'quit' to exit): ")
#         if text.lower() == "quit":
#             break

#         # Run regex + ML detection, merge, and redact
#         spans = merge_spans(regex_spans(text) + ml_spans(text))
#         print("\nDetected spans:")
#         for s in spans:
#             print(f"  {s['label']} ({s['score']:.2f}): '{text[s['start']:s['end']]}'")

#         redacted = redact(text)
#         print("\nRedacted output:")
#         print(redacted)

def detect_pii(text):
    spans = merge_spans(regex_spans(text) + ml_spans(text))
    return spans
    results = []
    for i, span in enumerate(spans, start=1):
        results.append({
            f'Email_{i}':{
            'label': span['label'],
            'score': round(span['score'], 4),
            }
        })
    return results

    {Email_1: ["EMAIL", {score: 1.0}]}