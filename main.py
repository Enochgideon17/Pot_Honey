from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
from dotenv import load_dotenv
from groq import Groq
import re
import requests
from pymongo import MongoClient

# ---------------- ENV ----------------
load_dotenv()

API_KEY = os.getenv("API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MONGO_URL = os.getenv("MONGO_URL")

client = Groq(api_key=GROQ_API_KEY)

# ---------------- DB SAFE CONNECT ----------------
sessions = None
try:
    if MONGO_URL:
        mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=3000)
        db = mongo_client["honeypot_db"]
        sessions = db["sessions"]
        print("MongoDB Connected")
except Exception as e:
    print("MongoDB Error:", e)
    sessions = None

# ---------------- APP ----------------
app = FastAPI()

# ---------------- MODELS ----------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

# ---------------- SCAM DETECTION ----------------
def detect_scam(text: str):
    try:
        prompt = f"Is this a scam message? Reply only YES or NO.\nMessage: {text}"

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}]
        )

        answer = response.choices[0].message.content.lower()
        return "yes" in answer

    except Exception as e:
        print("AI Detection Error:", e)
        keywords = ["verify", "urgent", "blocked", "upi", "account", "suspend"]
        return any(k in text.lower() for k in keywords)

# ---------------- AGENT REPLY ----------------
def agent_reply(text: str):
    try:
        prompt = f"""
        You are a calm normal human chatting with a scammer.
        Ask natural clarifying questions. Do not reveal suspicion.
        Message: {text}
        """

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        print("Agent Error:", e)
        return "Could you please explain that a bit more?"

# ---------------- INTELLIGENCE EXTRACTION ----------------
def extract_intelligence(text: str):
    phones = re.findall(r"\+?\d{10,13}", text)
    upi = re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    links = re.findall(r"https?://\S+", text)

    suspicious_words = []
    for word in ["urgent", "verify", "blocked", "suspend", "immediately"]:
        if word in text.lower():
            suspicious_words.append(word)

    return {
        "phoneNumbers": phones,
        "upiIds": upi,
        "phishingLinks": links,
        "suspiciousKeywords": suspicious_words
    }

# ---------------- CALLBACK ----------------
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

# ---------------- API ENDPOINT ----------------
@app.post("/honeypot/message")
async def honeypot_api(request: HoneypotRequest, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    text = request.message.text
    scam_detected = detect_scam(text)

    reply = "Okay, could you explain more?"
    intelligence = {}

    if scam_detected:
        reply = agent_reply(text)
        intelligence = extract_intelligence(text)

    # ---------------- SAVE TO MONGO ----------------
    try:
        if sessions is not None:
            sessions.update_one(
                {"sessionId": request.sessionId},
                {
                    "$push": {
                        "messages": {
                            "sender": request.message.sender,
                            "text": text,
                            "timestamp": request.message.timestamp
                        }
                    }
                },
                upsert=True
            )
    except Exception as e:
        print("Mongo Save Error:", e)

    # ---------------- CALLBACK CONDITION ----------------
    total_msgs = len(request.conversationHistory)

    if scam_detected and total_msgs >= 6:
        send_callback(
            request.sessionId,
            scam_detected,
            intelligence,
            total_msgs
        )

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "reply": reply
    }
