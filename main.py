from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
import os
import re
import time
import random
import requests
from dotenv import load_dotenv

# ---------- ENV ----------
load_dotenv()
API_KEY = os.getenv("API_KEY", "supersecret123")

# ---------- APP ----------
app = FastAPI()

# ---------- SAFE JSON RESPONSE HELPERS ----------
def success_response(data: dict):
    return JSONResponse(
        status_code=200,
        content=data,
        media_type="application/json"
    )

def error_response(status_code: int, message: str):
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "error": {
                "code": status_code,
                "message": message
            }
        },
        media_type="application/json"
    )

# ---------- SESSION STORE (In-Memory) ----------
SESSIONS = {}

# ---------- ROOT ----------
@app.get("/")
def root():
    return success_response({"status": "ok", "message": "Honeypot API Running"})

# ---------- EMOTIONAL REPLIES ----------
EMOTIONAL_REPLIES = [
    "Oh no… that sounds serious. What should I do now?",
    "I'm really worried. Can you help me fix this?",
    "This is scary… is my money safe?",
    "Please explain, I don’t understand what’s happening.",
    "I’m nervous… what should I do next?",
    "Oh my… is this urgent?",
    "I didn’t expect this… can you guide me?"
]

def emotional_reply():
    return random.choice(EMOTIONAL_REPLIES)

# ---------- SCAM DETECTION ----------
def detect_scam(text: str):
    keywords = ["urgent", "otp", "verify", "blocked", "bank", "account", "suspend"]
    return any(k in text.lower() for k in keywords)

# ---------- INTELLIGENCE EXTRACTION ----------
def extract_intelligence(text: str):
    phones = re.findall(r"\+?\d{10,13}", text)
    upi = re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    links = re.findall(r"https?://\S+", text)

    return {
        "phoneNumbers": phones,
        "upiIds": upi,
        "phishingLinks": links,
        "suspiciousKeywords": []
    }

# ---------- FINAL CALLBACK ----------
def send_final_result(session_id, scam_detected, intelligence, metrics):
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "extractedIntelligence": intelligence,
        "engagementMetrics": metrics,
        "agentNotes": "Scammer used urgency and impersonation tactics"
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
    except:
        # Never crash API if callback fails
        pass

# ---------- MAIN ENDPOINT ----------
@app.post("/honeypot/message")
async def honeypot_api(request: Request, x_api_key: str = Header(None)):

    # ---------- AUTH CHECK ----------
    if x_api_key != API_KEY:
        return error_response(401, "Invalid API Key")

    try:
        body = await request.json()
    except:
        return error_response(400, "Invalid JSON body")

    session_id = body.get("sessionId", "default-session")
    message = body.get("message", {})
    text = message.get("text", "")

    if not text:
        return error_response(400, "Missing message text")

    # ---------- SESSION INITIALIZATION ----------
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {
            "start_time": time.time(),
            "message_count": 0
        }

    SESSIONS[session_id]["message_count"] += 1
    message_count = SESSIONS[session_id]["message_count"]

    # ---------- CORE LOGIC ----------
    scam_detected = detect_scam(text)
    reply = emotional_reply()
    intelligence = extract_intelligence(text)

    # ---------- FINAL SESSION OUTPUT ----------
    if scam_detected and message_count >= 5:
        duration = int(time.time() - SESSIONS[session_id]["start_time"])

        metrics = {
            "messageCount": message_count,
            "durationSec": duration
        }

        send_final_result(session_id, scam_detected, intelligence, metrics)

    # ---------- GUARANTEED CONTRACT RESPONSE ----------
    return success_response({
        "status": "success",
        "scamDetected": scam_detected,
        "reply": reply
    })
