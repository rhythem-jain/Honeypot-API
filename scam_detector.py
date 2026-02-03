"""
Scam Detector - Identifies if a message is a scam attempt
Uses keyword matching and pattern analysis with weighted scoring
"""

import re
from typing import Tuple, List

from intelligence_extractor import IntelligenceExtractor


class ScamDetector:
    """Detect scam intent from messages using pattern matching"""
    
    # Scam patterns with weights for confidence scoring
    SCAM_PATTERNS = {
        'urgency': {
            'patterns': [
                r'\bimmediately\b', r'\burgent\b', r'\btoday\b',
                r'\bnow\b', r'\basap\b', r'\bquickly\b',
                r'\bexpir(e|ing|ed)\b', r'\blast chance\b',
                r'\blimited time\b', r'\bact fast\b', r'\bhurry\b'
            ],
            'weight': 2,
            'description': 'Urgency tactics'
        },
        'threat': {
            'patterns': [
                r'\bblock(ed)?\b', r'\bsuspend(ed)?\b',
                r'\bdeactivat(e|ed)\b', r'\bterminate(d)?\b',
                r'\bfreez(e|ing)\b', r'\blegal action\b',
                r'\bpolice\b', r'\barrest\b', r'\bfine\b',
                r'\bpenalty\b'
            ],
            'weight': 3,
            'description': 'Threat-based manipulation'
        },
        'sensitive_request': {
            'patterns': [
                r'\botp\b', r'\bpin\b', r'\bpassword\b',
                r'\bcvv\b', r'\bcard number\b', r'\bexpiry\b',
                r'\bbank account\b', r'\baccount number\b',
                r'\bupi\s*(id|pin)?\b', r'\baadhaar\b', r'\bpan\b',
                r'\bshare\b.*\b(details|info)\b'
            ],
            'weight': 4,
            'description': 'Request for sensitive information'
        },
        'lottery': {
            'patterns': [
                r'\bwon\b', r'\bwinner\b', r'\blottery\b',
                r'\bprize\b', r'\bclaim\b', r'\bcongratulation\b',
                r'\blucky\b', r'\bselected\b', r'\bcash prize\b',
                r'\breward\b'
            ],
            'weight': 4,
            'description': 'Lottery/Prize scam'
        },
        'financial_bait': {
            'patterns': [
                r'\brefund\b', r'\bcashback\b', r'\breward\b',
                r'\bfree\b', r'\bbonus\b', r'\bloan approved\b',
                r'\bcredit\b.*\bapproved\b', r'\bmoney\b.*\btransfer\b'
            ],
            'weight': 3,
            'description': 'Financial bait'
        },
        'impersonation': {
            'patterns': [
                r'\bbank\s*(manager|officer)\b', r'\brbi\b',
                r'\bgovernment\b', r'\bincome\s*tax\b',
                r'\bcustomer\s*(care|support)\b', r'\bofficial\b',
                r'\bauthorized\b', r'\bverified\b'
            ],
            'weight': 3,
            'description': 'Authority impersonation'
        },
        'link_request': {
            'patterns': [
                r'\bclick\s*(here|link|button)\b', r'\bvisit\b',
                r'\bopen\s*(link|url)\b', r'\bdownload\b',
                r'https?://', r'\bbit\.ly\b', r'\btinyurl\b'
            ],
            'weight': 2,
            'description': 'Suspicious link sharing'
        },
        'kyc': {
            'patterns': [
                r'\bkyc\b', r'\bverif(y|ication)\b',
                r'\bupdate\b.*\b(details|info|account)\b',
                r'\bmandatory\b', r'\bcompulsory\b'
            ],
            'weight': 3,
            'description': 'KYC/Verification scam'
        }
    }
    
    # Minimum score to consider as scam
    SCAM_THRESHOLD = 5
    
    @classmethod
    def detect_scam(
        cls,
        message: str,
        conversation_history: List[dict] = None
    ) -> Tuple[bool, float, List[str], str]:
        """
        Detect if a message is a scam attempt
        
        Args:
            message: The message to analyze
            conversation_history: Previous messages in conversation
        
        Returns:
            Tuple of (is_scam, confidence_score, detected_types, scam_notes)
        """
        text = message.lower()
        total_score = 0
        detected_types = []
        
        # Check each pattern category
        for category, data in cls.SCAM_PATTERNS.items():
            for pattern in data['patterns']:
                if re.search(pattern, text, re.IGNORECASE):
                    total_score += data['weight']
                    if category not in detected_types:
                        detected_types.append(category)
                    break  # Only count each category once
        
        # Analyze conversation history for cumulative patterns
        if conversation_history:
            history_text = " ".join([
                msg.get("text", "") for msg in conversation_history
                if msg.get("sender") == "scammer"
            ]).lower()
            
            # Add bonus score for patterns in history
            for category, data in cls.SCAM_PATTERNS.items():
                for pattern in data['patterns']:
                    if re.search(pattern, history_text, re.IGNORECASE):
                        total_score += data['weight'] * 0.5
                        break
        
        # Check for intelligence indicators (UPI, phone, URLs)
        full_text = message
        if conversation_history:
            full_text += " " + " ".join([m.get("text", "") for m in conversation_history])
        
        intel = IntelligenceExtractor.extract_all(full_text)
        
        intel_boost = 0
        if intel["upiIds"]:
            intel_boost += 0.15
        if intel["phoneNumbers"]:
            intel_boost += 0.1
        if intel["phishingLinks"]:
            intel_boost += 0.2
        
        # Calculate confidence (0 to 1)
        max_possible_score = sum(d['weight'] for d in cls.SCAM_PATTERNS.values())
        base_confidence = min(total_score / max_possible_score, 1.0)
        confidence = min(1.0, base_confidence + intel_boost)
        
        # Determine if it's a scam
        is_scam = total_score >= cls.SCAM_THRESHOLD or confidence >= 0.5
        
        # Generate notes
        notes = []
        if detected_types:
            type_descriptions = [
                cls.SCAM_PATTERNS[t]['description'] 
                for t in detected_types 
                if t in cls.SCAM_PATTERNS
            ]
            notes.append(f"Detected: {', '.join(type_descriptions)}")
        if intel["upiIds"]:
            notes.append(f"UPI IDs found: {', '.join(intel['upiIds'])}")
        if intel["phishingLinks"]:
            notes.append("Suspicious URLs detected")
        if intel["phoneNumbers"]:
            notes.append(f"Phone numbers found: {', '.join(intel['phoneNumbers'])}")
        
        scam_notes = "; ".join(notes) if notes else "No specific scam indicators"
        
        return is_scam, confidence, detected_types, scam_notes
    
    @classmethod
    def get_scam_type(cls, detected_patterns: List[str]) -> str:
        """Determine the primary type of scam based on detected patterns"""
        if 'lottery' in detected_patterns:
            return "Lottery/Prize Scam"
        elif 'kyc' in detected_patterns:
            return "KYC/Verification Scam"
        elif 'financial_bait' in detected_patterns:
            return "Financial Fraud"
        elif 'threat' in detected_patterns:
            return "Threat-based Scam"
        elif 'impersonation' in detected_patterns:
            return "Impersonation Scam"
        elif 'sensitive_request' in detected_patterns:
            return "Data Theft Scam"
        elif 'link_request' in detected_patterns:
            return "Phishing Scam"
        elif 'urgency' in detected_patterns:
            return "Urgency-based Scam"
        else:
            return "General Scam"
