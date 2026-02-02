from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
API_KEY = os.getenv("API_KEY") 
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

app = FastAPI()

# ---------------------------
# Request Models
# ---------------------------

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


# ---------------------------
# Basic Scam Detection
# ---------------------------

def detect_scam(text: str):
    try:
        prompt = f"""
        Determine if the following message is a scam.
        Answer ONLY YES or NO.

        Message: {text}
        """

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}]
        )

        answer = response.choices[0].message.content.strip().lower()
        return "yes" in answer

    except Exception:
        keywords = ["verify", "urgent", "blocked", "upi", "account", "suspend"]
        text = text.lower()
        return any(word in text for word in keywords)


        






# ---------------------------
# AI Agent Reply (Basic Demo)
# ---------------------------

def agent_reply():
    return "Why is my account being suspended?"


# ---------------------------
# API Endpoint
# ---------------------------

@app.post("/honeypot/message")
async def honeypot_api(
    request: HoneypotRequest,
    x_api_key: str = Header(None)
):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    scam_detected = detect_scam(request.message.text)

    if scam_detected:
        reply = agent_reply()
    else:
        reply = "Okay, can you explain more?"

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "reply": reply
    }
    
