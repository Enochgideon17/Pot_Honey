from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
from dotenv import load_dotenv
import re
import requests
from pymongo import MongoClient
import random

# ---------- ENV ----------
load_dotenv()

API_KEY = os.getenv("API_KEY", "supersecret123")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MONGO_URL = os.getenv("MONGO_URL")

# ---------- OPTIONAL GROQ ----------
groq_client = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
    except:
        groq_client = None

# ---------- MONGO SAFE CONNECT ----------
sessions = None
try:
    if MONGO_URL:
        mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=3000)
        db = mongo_client["honeypot_db"]
        sessions = db["sessions"]
        print("MongoDB Connected")
except Exception as e:
    print("Mongo Error:", e)

# ---------- APP ----------
app = FastAPI()

@app.get("/")
def root():
    return {"message": "Honeypot API Running"}

# ---------- MODELS ----------
class Message(BaseModel):
    sender: str = "unknown"
    text: str = ""
    timestamp: str = ""

class HoneypotRequest(BaseModel):
    sessionId: str = "default-session"
    message: Optional[Message] = Message()
    conversationHistory: Optional[List[Message]] = []

# ---------- SCAM DETECTION ----------
def detect_scam(text: str):
    if not text:
        return False

    # AI detection if Groq available
    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama3-8b-8192",
                messages=[{"role": "user", "content": f"Is this a scam? YES or NO.\n{text}"}]
            )
            ans = response.choices[0].message.content.lower()
            return "yes" in ans
        except:
            pass

    # fallback keyword rule
    keywords = ["urgent", "otp", "verify", "blocked", "bank", "account", "suspend"]
    return any(k in text.lower() for k in keywords)

# ---------- EMOTIONAL REPLIES ----------
EMOTIONAL_REPLIES = [
    "Oh no, that sounds serious… what exactly happened?",
    "I’m really worried now… can you explain more?",
    "Wait, my account is blocked? What should I do?",
    "This is scary… please tell me more details.",
    "I don’t understand… why is this happening?",
    "Is my money safe? I’m really concerned.",
    "That sounds urgent… what do I need to do now?"
]

def emotional_reply():
    return random.choice(EMOTIONAL_REPLIES)

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

# ---------- CALLBACK ----------
def send_callback(session_id, scam_detected, intelligence, total_msgs):
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": intelligence,
        "agentNotes": "Scammer used urgency tactics"
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
    except:
        pass

# ---------- ENDPOINT ----------
@app.post("/honeypot/message")
async def honeypot_api(request: Optional[HoneypotRequest] = None,
                       x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # SAFE DEFAULTS
    if not request:
        request = HoneypotRequest()

    text = request.message.text if request.message else ""

    scam_detected = detect_scam(text)
    reply = emotional_reply() if scam_detected else "Okay… can you explain more?"
    intelligence = extract_intelligence(text)

    # ---------- SAVE MONGO ----------
    try:
        if sessions:
            sessions.update_one(
                {"sessionId": request.sessionId},
                {"$push": {"messages": {"text": text}}},
                upsert=True
            )
    except:
        pass

    # ---------- CALLBACK ----------
    total_msgs = len(request.conversationHistory)
    if scam_detected and total_msgs >= 5:
        send_callback(request.sessionId, scam_detected, intelligence, total_msgs)

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "reply": reply
    }
