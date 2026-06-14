import os
import json
import requests
from groq import Groq
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_with_gemini(text, input_type):
    prompt = f"""
You are a scam detection expert. Be accurate and fair — do NOT mark safe messages as suspicious.

Analyze this {input_type} message carefully:

Message: "{text}"

SCORING RULES:
- Score 0-39 = SAFE: Normal messages like appointments, delivery updates, OTP from bank you requested, school messages, office messages, greetings
- Score 40-69 = SUSPICIOUS: Unusual requests, unverified offers, asking for personal info, unknown senders with offers
- Score 70-100 = SCAM: Asking for OTP, lottery wins, fake KYC, fake prizes, suspicious links, asking for money, threatening account block

IMPORTANT RULES:
- A bank OTP you requested yourself is SAFE
- Doctor or hospital appointment reminders are SAFE
- School or college messages are SAFE
- Delivery updates from known apps like Swiggy, Zomato, Amazon are SAFE
- Friends or family messages are SAFE
- Only mark SUSPICIOUS or SCAM if there are real red flags
- If no red flags exist, red_flags list should be empty []
- safety_advice for SAFE messages should be "This message looks genuine. No action needed."

Respond with this exact JSON only (no extra text, no markdown, no code fences):
{{
  "risk_score": <number 0-100>,
  "verdict": "<SAFE / SUSPICIOUS / SCAM>",
  "explanation": "<Simple English explanation in 2-3 sentences that an elderly person can understand>",
  "scam_type": "<type of scam or Not a scam>",
  "red_flags": ["<flag1>", "<flag2>"],
  "safety_advice": "<One simple action they should take>"
}}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )

    text_result = response.choices[0].message.content.strip()

    if text_result.startswith("```"):
        text_result = text_result.split("```")[1]
        if text_result.startswith("json"):
            text_result = text_result[4:]
        text_result = text_result.strip()

    start = text_result.find("{")
    end = text_result.rfind("}") + 1
    if start != -1 and end != 0:
        text_result = text_result[start:end]

    result = json.loads(text_result)

    score = result.get("risk_score", 0)
    if score < 40:
        result["verdict"] = "SAFE"
    elif score < 70:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "SCAM"

    return result

def check_url_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None

    headers = {"x-apikey": api_key}

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code == 200:
        data = response.json()
        scan_id = data["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers
        )

        if result.status_code == 200:
            stats = result.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            return {
                "malicious_count": malicious,
                "is_dangerous": malicious > 2
            }
    return None

def translate_to_tamil(text):
    try:
        translated = GoogleTranslator(source='en', target='ta').translate(text)
        return translated
    except Exception:
        return ""

def generate_voice_alert(text, filename):
    from gtts import gTTS

    audio_folder = os.path.join("static", "audio")
    os.makedirs(audio_folder, exist_ok=True)

    filepath = os.path.join(audio_folder, filename)
    tts = gTTS(text=text, lang='en', slow=True)
    tts.save(filepath)
    return filepath