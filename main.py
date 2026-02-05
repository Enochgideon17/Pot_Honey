from fastapi import FastAPI, Header, HTTPException, Request
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

# ---------- EMOTIONAL REPLIES ----------
EMOTIONAL_REPLIES = [
    "Oh no… that sounds serious. What should I do now?",
    "I'm really worried. Can you help me fix this?",
    "This is scary… is my money safe?",
    "Please explain, I don’t understand what’s happening.",
    "Oh gosh, I didn’t expect this today. What should I do?",
    "I’m nervous now… can you guide me step by step?",
    "Wait, is this urgent? I’m getting anxious."
]

def emotional_reply():
    return random.choice(EMOTIONAL_REPLIES)

# ---------- SCAM DETECTION ----------
def detect_scam(text: str):
    if not text:
        return False

    # AI detection
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

    # fallback keywords
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

# ---------- CALLBACK ----------
def send_callback(session_id, scam_detected, intelligence, total_msgs):
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": intelligence,
        "agentNotes": "Scammer used urgency and verification tactics"
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
        print("Callback Sent")
    except Exception as e:
        print("Callback Error:", e)

# ---------- MAIN ENDPOINT ----------
@app.post("/honeypot/message")
async def honeypot_api(request: Request, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    try:
        body = await request.json()
    except:
        body = {}

    # Flexible JSON Parsing
    session_id = body.get("sessionId", "default-session")
    message = body.get("message", {})

    text = message.get("text", body.get("text", "Hello"))
    sender = message.get("sender", "scammer")
    timestamp = message.get("timestamp", "now")
    history = body.get("conversationHistory", [])

    scam_detected = detect_scam(text)
    reply = emotional_reply()
    intelligence = extract_intelligence(text)

    # ---------- SAVE TO MONGO ----------
    try:
        if sessions:
            sessions.update_one(
                {"sessionId": session_id},
                {"$push": {"messages": {"text": text}}},
                upsert=True
            )
    except:
        pass

    # ---------- FINAL CALLBACK ----------
    if scam_detected and len(history) >= 5:
        send_callback(session_id, scam_detected, intelligence, len(history))

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "reply": reply
    }
