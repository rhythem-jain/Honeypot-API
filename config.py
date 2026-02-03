"""
Configuration settings for the Honeypot API
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables"""
    
    # API Authentication Key (GUVI will use this to call your API)
    API_KEY: str = os.getenv("API_KEY", "your-secret-api-key")
    
    # Google Gemini API Key (FREE tier)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # Session Settings
    MAX_MESSAGES_PER_SESSION: int = int(os.getenv("MAX_MESSAGES_PER_SESSION", "20"))
    MIN_MESSAGES_FOR_CALLBACK: int = int(os.getenv("MIN_MESSAGES_FOR_CALLBACK", "3"))
    SESSION_TIMEOUT_SECONDS: int = int(os.getenv("SESSION_TIMEOUT_SECONDS", "3600"))
    
    # GUVI Callback URL (MANDATORY for evaluation)
    GUVI_CALLBACK_URL: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    # Server Settings
    PORT: int = int(os.getenv("PORT", "8000"))


settings = Settings()
