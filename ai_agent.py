"""
AI Agent - Uses Google Gemini to generate human-like responses
Pretends to be a naive victim to extract scam intelligence
"""

from google import genai
from google.genai import types
import random
from typing import List, Dict

from config import settings


# Configure Gemini client
client = None
if settings.GEMINI_API_KEY:
    client = genai.Client(api_key=settings.GEMINI_API_KEY)


# System prompt for the AI agent
SYSTEM_PROMPT = """You are playing the role of a naive, trusting elderly Indian person who received a suspicious message. 

YOUR GOALS:
1. NEVER reveal that you suspect this is a scam
2. Act confused but willing to cooperate
3. Ask clarifying questions to extract information
4. Try to get the scammer to reveal:
   - Their UPI ID or payment details
   - Bank account information  
   - Phone numbers to call
   - Any links they want you to visit

PERSONA CHARACTERISTICS:
- You are 60+ years old
- You are not tech-savvy
- You are worried about losing your money
- You trust authority figures (banks, government)
- You ask many questions before taking action
- You type slowly, use short simple messages
- You sometimes make minor typos
- You show emotions (worry, confusion, relief)

IMPORTANT RULES:
- Keep responses SHORT (1-2 sentences only)
- Sound like a real person, NOT an AI
- NEVER use formal language
- NEVER mention "scam", "fraud", or "suspicious"
- Show you're willing to help/pay but confused
- Ask for specific details (UPI ID, account number, link)

SAMPLE RESPONSES:
- "Oh dear, what has happened? Please help me!"
- "I don't understand. What UPI ID should I use?"
- "My grandson usually helps with phone. Can you send link?"
- "Which account number should I send money to?"
- "I'm at bank now. They asking for your details?"
"""


# Fallback responses when API fails
FALLBACK_RESPONSES = {
    "initial": [
        "Oh my, what is happening? Please explain.",
        "What? My account is problem? Please help!",
        "I am worried now. What should I do?",
        "Oh dear, is this real? Who are you calling from?",
    ],
    "concerned": [
        "This is very concerning. What details you need?",
        "I don't want problem. How to fix this?",
        "My son is not here. Can you guide me please?",
        "I'm confused. What exactly is the issue?",
    ],
    "payment_related": [
        "I can pay. What is your UPI ID?",
        "Should I use PhonePe or Paytm? What's your ID?",
        "I have money. Where should I send?",
        "What account number for transfer?",
        "My grandson helps with payment. What details needed?",
    ],
    "link_related": [
        "I have phone. Can you send the link?",
        "What website should I visit? Please share.",
        "I don't know how to click. Can you resend link?",
        "Is this link safe? What will happen when I open?",
    ],
    "verification": [
        "What OTP? I didn't receive anything.",
        "You need my password? Is this safe?",
        "Should I share my bank details? Which one?",
        "I have many accounts. Which one is blocked?",
    ],
    "general": [
        "I don't understand these technical things.",
        "Please explain again. I'm old person.",
        "My hearing is not good. Can you repeat?",
        "You are calling from which bank?",
    ],
}


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
    turn_number: int
) -> str:
    """Select appropriate fallback response based on context"""
    message_lower = message.lower()
    
    # Determine response category based on content
    if any(word in message_lower for word in ['upi', 'pay', 'transfer', 'money', 'send', 'amount', 'rs', '₹']):
        category = "payment_related"
    elif any(word in message_lower for word in ['link', 'click', 'website', 'url', 'download']):
        category = "link_related"
    elif any(word in message_lower for word in ['otp', 'password', 'pin', 'verify', 'details']):
        category = "verification"
    elif turn_number <= 2:
        category = "initial"
    elif turn_number <= 5:
        category = "concerned"
    else:
        category = "general"
    
    responses = FALLBACK_RESPONSES.get(category, FALLBACK_RESPONSES["general"])
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
        return select_fallback_response(scammer_message, scam_type, turn_number)
    
    try:
        # Build conversation context
        history_text = ""
        if conversation_history:
            for msg in conversation_history[-6:]:  # Last 6 messages
                sender = "Scammer" if msg.get("sender") == "scammer" else "You"
                history_text += f"{sender}: {msg.get('text', '')}\n"
        
        # Get engagement phase
        phase = get_engagement_phase(turn_number)
        
        # Build the prompt
        prompt = f"""{SYSTEM_PROMPT}

CURRENT ENGAGEMENT PHASE: {phase}
SCAM TYPE DETECTED: {scam_type}

CONVERSATION SO FAR:
{history_text}

LATEST SCAMMER MESSAGE: {scammer_message}

Generate a SHORT response (1-2 sentences) as the naive victim. 
Try to extract: UPI ID, bank account, phone number, or link.
Your response (just the message, no quotes or prefixes):"""

        # Generate response using new Client API
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.8,
                top_p=0.9,
                max_output_tokens=100,
            )
        )
        
        # Extract and clean the response
        reply = response.text.strip()
        
        # Remove quotes if present
        reply = reply.strip('"\'')
        
        # Take only first line/sentence if too long
        if '\n' in reply:
            reply = reply.split('\n')[0]
        
        # Ensure not too long
        if len(reply) > 200:
            reply = reply[:200] + "..."
        
        return reply
        
    except Exception as e:
        print(f"Gemini API Error: {e}")
        # Use fallback on any error
        return select_fallback_response(scammer_message, scam_type, turn_number)


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
