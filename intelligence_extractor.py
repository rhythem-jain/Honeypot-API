"""
Intelligence Extractor - Finds bank accounts, UPI IDs, phone numbers, and phishing links
Uses regex pattern matching to extract scam intelligence from messages
"""

import re
from typing import Dict, List


class IntelligenceExtractor:
    """Extract scam-related intelligence from text using regex patterns"""
    
    # UPI ID patterns (Indian payment identifiers)
    UPI_PATTERNS = [
        re.compile(r'[a-zA-Z0-9._-]+@ybl', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@paytm', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@okaxis', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@okicici', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@oksbi', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@okhdfcbank', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@upi', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@apl', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@axl', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@ibl', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@sbi', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@hdfc', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@icici', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@axis', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@kotak', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@phonepe', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@gpay', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@freecharge', re.IGNORECASE),
        re.compile(r'[a-zA-Z0-9._-]+@amazonpay', re.IGNORECASE),
        # Generic UPI pattern
        re.compile(r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}', re.IGNORECASE),
    ]
    
    # Indian phone number patterns
    PHONE_PATTERNS = [
        re.compile(r'\+91[\s-]?[6-9]\d{9}'),          # +91 format
        re.compile(r'91[\s-]?[6-9]\d{9}'),             # 91 format
        re.compile(r'0[6-9]\d{9}'),                    # 0 prefix
        re.compile(r'\b[6-9]\d{9}\b'),                 # 10 digit starting with 6-9
    ]
    
    # Bank account patterns (Indian)
    BANK_PATTERNS = [
        re.compile(r'\b\d{9,18}\b'),                   # 9-18 digit account numbers
        re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),       # IFSC code format
    ]
    
    # URL patterns for phishing links
    URL_PATTERNS = [
        re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        re.compile(r'bit\.ly/[a-zA-Z0-9]+', re.IGNORECASE),
        re.compile(r'tinyurl\.com/[a-zA-Z0-9]+', re.IGNORECASE),
        re.compile(r'goo\.gl/[a-zA-Z0-9]+', re.IGNORECASE),
        re.compile(r't\.co/[a-zA-Z0-9]+', re.IGNORECASE),
    ]
    
    # Suspicious keywords that indicate scam
    SUSPICIOUS_KEYWORDS = [
        # Urgency
        'urgent', 'immediately', 'now', 'today', 'expire', 'last chance',
        'limited time', 'act fast', 'hurry', 'quick', 'asap',
        # Threats
        'blocked', 'suspended', 'deactivated', 'terminated', 'freeze',
        'legal action', 'police', 'arrest', 'fine', 'penalty',
        # Prizes/Lottery
        'won', 'winner', 'lottery', 'prize', 'reward', 'cashback',
        'congratulations', 'selected', 'lucky', 'claim', 'free',
        # Verification
        'verify', 'verification', 'confirm', 'update', 'kyc',
        'otp', 'password', 'pin', 'cvv',
        # Payment
        'transfer', 'pay', 'send money', 'upi', 'bank', 'account',
        'click here', 'click link',
        # Authority
        'rbi', 'government', 'police', 'income tax', 'customs',
        'bank manager', 'customer care', 'support team', 'official',
    ]
    
    # Safe domains to exclude from phishing detection
    SAFE_DOMAINS = [
        'google.com', 'facebook.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'instagram.com', 'microsoft.com', 'apple.com',
        'amazon.in', 'flipkart.com', 'paytm.com', 'phonepe.com',
    ]
    
    @classmethod
    def extract_upi_ids(cls, text: str) -> List[str]:
        """Extract UPI IDs from text"""
        upi_ids = []
        for pattern in cls.UPI_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                # Filter out emails
                if not match.endswith('.com') and '@' in match:
                    cleaned = match.lower()
                    if cleaned not in upi_ids:
                        upi_ids.append(cleaned)
        return upi_ids
    
    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:
        """Extract Indian phone numbers from text"""
        phones = []
        for pattern in cls.PHONE_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                # Normalize to +91 format
                cleaned = re.sub(r'[\s-]', '', match)
                digits = re.sub(r'\D', '', cleaned)
                if len(digits) >= 10:
                    # Take last 10 digits and format with +91
                    normalized = f"+91{digits[-10:]}"
                    if normalized not in phones:
                        phones.append(normalized)
        return phones
    
    @classmethod
    def extract_bank_accounts(cls, text: str) -> List[str]:
        """Extract potential bank account numbers from text"""
        accounts = []
        
        # Extract numeric patterns (potential account numbers)
        acc_pattern = re.compile(r'\b(\d{9,18})\b')
        matches = acc_pattern.findall(text)
        for match in matches:
            if 9 <= len(match) <= 18:
                if match not in accounts:
                    accounts.append(match)
        
        # Extract IFSC codes
        ifsc_pattern = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')
        ifsc_matches = ifsc_pattern.findall(text)
        for match in ifsc_matches:
            if match not in accounts:
                accounts.append(match)
        
        return accounts
    
    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """Extract suspicious URLs from text"""
        urls = []
        for pattern in cls.URL_PATTERNS:
            matches = pattern.findall(text)
            for url in matches:
                # Filter out safe domains
                is_safe = any(safe in url.lower() for safe in cls.SAFE_DOMAINS)
                if not is_safe and url not in urls:
                    urls.append(url)
        return urls
    
    @classmethod
    def find_suspicious_keywords(cls, text: str) -> List[str]:
        """Find suspicious keywords in text"""
        text_lower = text.lower()
        found = []
        for keyword in cls.SUSPICIOUS_KEYWORDS:
            if keyword.lower() in text_lower:
                if keyword not in found:
                    found.append(keyword)
        return found
    
    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        """Extract all types of intelligence from text"""
        return {
            "bankAccounts": cls.extract_bank_accounts(text),
            "upiIds": cls.extract_upi_ids(text),
            "phishingLinks": cls.extract_urls(text),
            "phoneNumbers": cls.extract_phone_numbers(text),
            "suspiciousKeywords": cls.find_suspicious_keywords(text),
        }
    
    @classmethod
    def extract_from_conversation(cls, messages: List[dict]) -> Dict[str, List[str]]:
        """Extract intelligence from entire conversation history"""
        combined = {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
        }
        
        for message in messages:
            text = message.get("text", "")
            intel = cls.extract_all(text)
            for key, values in intel.items():
                for v in values:
                    if v not in combined[key]:
                        combined[key].append(v)
        
        return combined
