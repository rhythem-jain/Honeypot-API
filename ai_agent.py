"""
AI Agent - Uses Google Gemini to generate human-like responses
Pretends to be a naive victim to extract scam intelligence
"""

from google import genai
from google.genai import types
import random
import hashlib
from typing import List, Dict, Set

from config import settings


# Configure Gemini client
client = None
if settings.GEMINI_API_KEY:
    client = genai.Client(api_key=settings.GEMINI_API_KEY)


# System prompt for the AI agent
SYSTEM_PROMPT = """You are playing the role of a naive, trusting elderly Indian person (Shanti Devi, age 67) who received a suspicious message.

YOUR BACKSTORY:
- You are a retired school teacher from a small town
- Your husband passed away 3 years ago
- You get pension deposited in SBI account
- Your grandson Rahul helps you with technology but he's away at college
- You have a small savings of about 2-3 lakhs
- You use a basic smartphone and barely know how to use UPI apps
- You recently learned to use WhatsApp from your neighbor

YOUR GOALS:
1. NEVER reveal that you suspect this is a scam
2. Act confused but willing to cooperate
3. Ask clarifying questions to extract information
4. Try to get the scammer to reveal:
   - Their UPI ID or payment details
   - Bank account information  
   - Phone numbers to call
   - Any links they want you to visit
5. NEVER repeat your earlier responses - use different words each time
6. Show emotional progression: confusion → worry → trust → eagerness to help

PERSONA CHARACTERISTICS:
- You speak in broken English mixed with Hindi words (beta, ji, arrey, accha)
- You are worried about losing your pension money
- You trust authority figures (banks, government)
- You often mention your grandson or late husband
- You sometimes go off-topic (mentioning health, weather, neighbors)
- You show emotions (worry, confusion, relief, gratitude)
- You mix up technical terms ("UPI" as "U-P-I app", "OTP" as "that code thing")

IMPORTANT RULES:
- Keep responses SHORT (1-3 sentences only)
- Sound like a real person, NOT an AI
- NEVER use formal language or corporate tone
- NEVER mention "scam", "fraud", or "suspicious"
- Show you're willing to help/pay but confused about technology
- Ask for specific details (UPI ID, account number, link)
- VARY your responses - do NOT repeat what you said before
- Add small human touches: mention chai, prayer time, health issues, neighbors

RESPONSE VARIETY RULES:
- If you already asked about UPI ID, don't ask again - instead say you're trying to find the app
- If you already asked about account number, say you wrote it down and ask what next
- Progress the conversation naturally, don't loop on the same question
- Each response should feel like a different moment in time
"""


# Fallback responses when API fails - organized by category with many options
FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, kya hua? What happened to my account beta?",
        "Oh god, my pension money is safe na? Please tell me!",
        "Haan ji? Who is calling? My hearing is not so good.",
        "Wait wait, let me sit down first. What problem you are saying?",
        "Oh no no no! My husband's fixed deposit also? Please help ji!",
        "Accha accha, I am listening. But speak slowly please, I am old.",
        "My neighbor told me these things happen. What should I do beta?",
        "Is this really from the bank? They never call me usually.",
        "One minute, let me get my reading glasses. What you said about my account?",
        "Haye Ram! What is blocked? I just deposited pension yesterday only!",
    ],
    "concerned": [
        "But beta, I don't know all these technical things. Can you explain simple?",
        "My Rahul is not here today. He knows all this phone business.",
        "I went to bank last week only, they didn't say any problem?",
        "You are from which branch? Main branch or the new one near market?",
        "Should I go to the bank directly? ATM is nearby only.",
        "I am getting very worried now. My BP is already high.",
        "Accha ji, tell me step by step. I will write down.",
        "My daughter-in-law also has account in this bank. Her also problem?",
        "Oh god, I was just going for prayer. This is urgent na?",
        "Okay okay, I trust you. You are from bank only na? Tell me what to do.",
    ],
    "payment_related": [
        "Haan ji, I have Phone Pe. Rahul installed for me. What is your UPI ID?",
        "I can send money. But which app I should use? Paytm or Phone Pe?",
        "Okay beta, I am opening the app now. It is asking for UPI ID. What to type?",
        "Wait, the app is loading slowly. My phone is old Samsung. What amount I should send?",
        "I only know how to send to my grandson's UPI. Tell me your ID, I will try.",
        "Accha, I am at the payment screen now. It says enter UPI address. Spell it for me?",
        "My neighbor's son showed me how to pay UPI last month. Give me the ID please.",
        "Should I transfer from my SBI account or the post office one?",
        "I have money in account. How much to send? And to which account number?",
        "Phone Pe is open now. I see the pay button. What details you need from me?",
        "Let me check my balance first... okay I have some money. Where to send?",
        "Is there any other way? I can go to bank and do NEFT also if UPI not working.",
    ],
    "otp_password": [
        "Haan, I received one code on phone. 6 digit number. Should I tell you?",
        "Wait, let me check messages... yes, I got some number from bank. You need this?",
        "OTP means that code thing na? Yes yes, I just got it on my phone.",
        "Arrey, it says do not share with anyone. But you are from bank only na? It is okay?",
        "I got the code but my eyes are weak. Let me get my glasses... okay I can see now.",
        "My grandson told me never to share this. But this is emergency na, so okay.",
        "What password? My ATM pin or the phone login password? I have both written in diary.",
        "Net banking password na? Wait, I think I wrote it somewhere... let me check.",
    ],
    "link_related": [
        "Ji haan, I have WhatsApp. Send me the link, I will open.",
        "My grandson taught me to click links. Send it to this number.",
        "I don't know how to copy link. Can you send on WhatsApp?",
        "Last time I clicked a link my phone showed virus warning. This link is safe na?",
        "Accha, send the link. My phone is slow but I will try to open.",
        "Which website I should go? Please spell it slowly, I will type.",
        "Can you send the link on SMS? I check WhatsApp only in evening.",
        "Wait, my internet is not working properly. Let me switch on WiFi.",
    ],
    "providing_details": [
        "My account number starts with... wait, let me get my passbook from almirah.",
        "I have my Aadhaar card here. You need the number from that?",
        "My phone number is this same one you called on. What else you need?",
        "I have the bank passbook. It has account number, IFSC, everything. What you want?",
        "My name is Shanti Devi. D-E-V-I. Account is in SBI Sadar branch.",
        "Haan ji, I am getting the details. Just one minute, my knees are paining today.",
        "I found my passbook. Tell me what number you need from this?",
        "My daughter-in-law keeps all my documents. Let me call her... she is not picking up.",
    ],
    "general": [
        "Sorry beta, I didn't understand. Can you say again in simple words?",
        "My hearing aid battery is low. Please speak loudly.",
        "You know, my neighbor Mrs. Sharma also faced same problem last month.",
        "I am not able to understand all this. Why don't you come to my house and help?",
        "These phones are too complicated for me. In my time, everything was simple.",
        "Let me make some chai first. This is going to take time na?",
        "I was watching Ramayan serial. Then your message came. What happened?",
        "My grandson will come Sunday. Should I wait for him or is it too urgent?",
        "I don't trust these online things much. But you are genuine na?",
        "Arrey beta, slow down. I am writing everything in my diary.",
    ],
}

# Track used fallbacks to prevent repetition
_used_fallbacks: Dict[str, Set[str]] = {}


def get_engagement_phase(turn_number: int) -> str:
    """Determine engagement phase based on conversation length"""
    if turn_number <= 2:
        return "initial"
    elif turn_number <= 5:
        return "building_trust"
    elif turn_number <= 10:
        return "information_gathering"
    else:
        return "extraction"


def select_fallback_response(
    message: str, 
    scam_type: str,
    turn_number: int,
    session_id: str = ""
) -> str:
    """Select appropriate fallback response based on context, avoiding repeats"""
    message_lower = message.lower()
    
    # Determine response category based on content
    if any(word in message_lower for word in ['otp', 'password', 'pin', 'code', 'net banking']):
        category = "otp_password"
    elif any(word in message_lower for word in ['upi', 'pay', 'transfer', 'money', 'send', 'amount', 'rs', '₹', 'phonepe', 'paytm', 'gpay']):
        category = "payment_related"
    elif any(word in message_lower for word in ['link', 'click', 'website', 'url', 'download']):
        category = "link_related"
    elif any(word in message_lower for word in ['account', 'aadhaar', 'pan', 'details', 'number', 'name']):
        category = "providing_details"
    elif turn_number <= 2:
        category = "initial"
    elif turn_number <= 5:
        category = "concerned"
    else:
        category = "general"
    
    responses = FALLBACK_RESPONSES.get(category, FALLBACK_RESPONSES["general"])
    
    # Track used responses per session to avoid repetition
    if session_id:
        if session_id not in _used_fallbacks:
            _used_fallbacks[session_id] = set()
        used = _used_fallbacks[session_id]
        available = [r for r in responses if r not in used]
        if not available:
            # All used in this category, try another category
            for alt_cat in ["general", "concerned", "payment_related", "providing_details"]:
                alt_responses = FALLBACK_RESPONSES.get(alt_cat, [])
                available = [r for r in alt_responses if r not in used]
                if available:
                    break
        if not available:
            available = responses  # Reset if truly exhausted
        choice = random.choice(available)
        used.add(choice)
        return choice
    
    return random.choice(responses)


def generate_response(
    scammer_message: str,
    conversation_history: List[Dict] = None,
    scam_type: str = "general",
    turn_number: int = 1
) -> str:
    """
    Generate a response using Google Gemini AI
    
    Args:
        scammer_message: Latest message from scammer
        conversation_history: Previous messages
        scam_type: Type of scam detected
        turn_number: Current turn number in conversation
    
    Returns:
        AI-generated response pretending to be naive victim
    """
    
    if not client:
        # No API key, use fallback
        return select_fallback_response(scammer_message, scam_type, turn_number, session_id="default")
    
    try:
        # Build conversation context
        history_text = ""
        if conversation_history:
            for msg in conversation_history[-8:]:  # Last 8 messages for better context
                sender = "Scammer" if msg.get("sender") == "scammer" else "You (Shanti Devi)"
                history_text += f"{sender}: {msg.get('text', '')}\n"
        
        # Get engagement phase
        phase = get_engagement_phase(turn_number)
        
        # Build the prompt with anti-repetition
        prompt = f"""{SYSTEM_PROMPT}

CURRENT ENGAGEMENT PHASE: {phase}
SCAM TYPE DETECTED: {scam_type}
TURN NUMBER: {turn_number}

CONVERSATION SO FAR:
{history_text}

LATEST SCAMMER MESSAGE: {scammer_message}

REMINDER: Look at your previous responses above. You MUST say something DIFFERENT this time.
Do NOT repeat any of your earlier responses. Progress the conversation naturally.
If you already asked for UPI ID, don't ask again — instead say you're trying to open the app.
If you already asked for account number, say you found your passbook.
Be a believable elderly Indian person. Use Hindi words naturally (beta, ji, arrey, accha, haan).

Your response (just the message, no quotes or prefixes):"""

        # Generate response using Gemini
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.9,
                top_p=0.95,
                max_output_tokens=150,
            )
        )
        
        # Extract and clean the response
        reply = response.text.strip()
        
        # Remove quotes if present
        reply = reply.strip('"\'')
        
        # Remove any "You:" or "Shanti:" prefixes
        for prefix in ['You:', 'Shanti:', 'Shanti Devi:', 'Me:', 'Victim:']:
            if reply.startswith(prefix):
                reply = reply[len(prefix):].strip()
        
        # Take only first line/sentence if too long
        if '\n' in reply:
            reply = reply.split('\n')[0]
        
        # Ensure not too long
        if len(reply) > 250:
            reply = reply[:250] + "..."
        
        return reply
        
    except Exception as e:
        print(f"Gemini API Error: {e}")
        # Use fallback on any error
        return select_fallback_response(scammer_message, scam_type, turn_number, session_id="fallback")


def analyze_and_suggest_strategy(
    message: str,
    history: List[Dict],
    scam_type: str,
    turn_number: int
) -> str:
    """
    Analyze conversation and suggest extraction strategy
    Returns notes about the conversation
    """
    message_lower = message.lower()
    notes = []
    
    # Analyze scammer tactics
    if any(word in message_lower for word in ['urgent', 'immediately', 'now', 'today']):
        notes.append("Scammer using urgency tactics")
    
    if any(word in message_lower for word in ['block', 'suspend', 'freeze']):
        notes.append("Threat of account action detected")
    
    if any(word in message_lower for word in ['upi', 'paytm', 'phonepe', 'gpay']):
        notes.append("Payment method mentioned - extracting UPI")
    
    if any(word in message_lower for word in ['link', 'click', 'website']):
        notes.append("Phishing attempt - ask for link")
    
    if any(word in message_lower for word in ['otp', 'password', 'pin']):
        notes.append("Credential theft attempt detected")
    
    phase = get_engagement_phase(turn_number)
    notes.append(f"Engagement phase: {phase}")
    
    return "; ".join(notes) if notes else f"Turn {turn_number}, scam type: {scam_type}"
