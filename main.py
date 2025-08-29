# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from collections import defaultdict
from model import model  # has detect_pii()

app = FastAPI()

# CORS for local React dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # lock down later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextPayload(BaseModel):
    text: str

class Detection(BaseModel):
    key: str
    label: str
    score: float
    original: str
    redacted: str
    start: int  
    end: int

TEXT_STORE = {"text": ""}

@app.post("/text")
async def set_text(payload: TextPayload):
    TEXT_STORE["text"] = payload.text
    return {"message": "Text stored"}

@app.get("/text")
async def get_text():
    return {"text": TEXT_STORE["text"]}

@app.post("/check", response_model=List[Detection])
async def check_text(payload: TextPayload):
    spans = model.detect_pii(payload.text)
    # spans should return: label, score, start, end

    results = []
    counters = defaultdict(int)
    redacted_text = payload.text

    # Replace all PII with placeholder keys
    for span in sorted(spans, key=lambda s: s["start"], reverse=True):
        label = span["label"].capitalize()
        value = payload.text[span["start"]:span["end"]] # original PII value
        counters[label] += 1
        key = f"{label}_{counters[label]}" # Person_1, Person_2, Email_1, etc.
        redacted_text = (
            redacted_text[:span["start"]] + key + redacted_text[span["end"]:]
        )
        results.append({
            "key": key,
            "label": label.upper(),
            "score": round(span["score"], 4),
            "original": payload.text[span["start"]:span["end"]],
            "redacted": key,
            "start": span["start"],
            "end": span["end"]
        })

    # Store the text for frontend highlighting
    TEXT_STORE["text"] = payload.text
    return list(reversed(results))  # reverse so instance numbers are sequential L→R