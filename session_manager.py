"""
Session Manager - Tracks conversation state and extracted intelligence
Uses in-memory storage for hackathon simplicity
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading

from config import settings


@dataclass
class ExtractedIntelligence:
    """Container for extracted scam intelligence"""
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "bankAccounts": list(set(self.bankAccounts)),
            "upiIds": list(set(self.upiIds)),
            "phishingLinks": list(set(self.phishingLinks)),
            "phoneNumbers": list(set(self.phoneNumbers)),
            "suspiciousKeywords": list(set(self.suspiciousKeywords))
        }
    
    def merge(self, other_intel: Dict[str, List[str]]) -> None:
        """Merge new intelligence into existing"""
        for key, values in other_intel.items():
            if hasattr(self, key):
                current = getattr(self, key)
                for v in values:
                    if v not in current:
                        current.append(v)


@dataclass 
class SessionState:
    """State for a single conversation session"""
    session_id: str
    scam_detected: bool = False
    scam_confidence: float = 0.0
    scam_type: str = ""
    messages: List[dict] = field(default_factory=list)
    intelligence: ExtractedIntelligence = field(default_factory=ExtractedIntelligence)
    agent_notes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    callback_sent: bool = False
    
    @property
    def total_messages(self) -> int:
        return len(self.messages)
    
    @property
    def is_expired(self) -> bool:
        timeout = timedelta(seconds=settings.SESSION_TIMEOUT_SECONDS)
        return datetime.utcnow() - self.last_activity > timeout
    
    @property
    def should_send_callback(self) -> bool:
        """Check if callback should be sent to GUVI"""
        return (
            self.scam_detected and
            not self.callback_sent and
            self.total_messages >= settings.MIN_MESSAGES_FOR_CALLBACK
        )
    
    @property
    def has_good_intel(self) -> bool:
        """Check if we've extracted valuable intelligence"""
        intel = self.intelligence
        return (
            len(intel.bankAccounts) > 0 or
            len(intel.upiIds) > 0 or
            len(intel.phishingLinks) > 0
        )
    
    @property
    def should_end_session(self) -> bool:
        """Check if session should end"""
        # End if max messages reached
        if self.total_messages >= settings.MAX_MESSAGES_PER_SESSION:
            return True
        # End if we have good intel and enough messages
        if self.has_good_intel and self.total_messages >= 8:
            return True
        return False


class SessionManager:
    """Thread-safe in-memory session manager"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._sessions: Dict[str, SessionState] = {}
        return cls._instance
    
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create new one"""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id)
            session = self._sessions[session_id]
            session.last_activity = datetime.utcnow()
            return session
    
    def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get session without creating"""
        return self._sessions.get(session_id)
    
    def add_message(
        self, 
        session_id: str, 
        sender: str, 
        text: str, 
        timestamp: str = None
    ) -> None:
        """Add message to session history"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.messages.append({
                    "sender": sender,
                    "text": text,
                    "timestamp": timestamp or datetime.utcnow().isoformat()
                })
                session.last_activity = datetime.utcnow()
    
    def update_scam_detection(
        self,
        session_id: str,
        is_scam: bool,
        confidence: float,
        scam_type: str
    ) -> None:
        """Update scam detection status"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                if is_scam:
                    session.scam_detected = True
                session.scam_confidence = max(session.scam_confidence, confidence)
                if scam_type:
                    session.scam_type = scam_type
    
    def add_intelligence(
        self, 
        session_id: str, 
        intel: Dict[str, List[str]]
    ) -> None:
        """Merge new intelligence into session"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.intelligence.merge(intel)
    
    def add_agent_note(self, session_id: str, note: str) -> None:
        """Add agent observation note"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and note and note not in session.agent_notes:
                session.agent_notes.append(note)
    
    def mark_callback_sent(self, session_id: str) -> None:
        """Mark that callback was sent to GUVI"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.callback_sent = True
    
    def get_session_data(self, session_id: str) -> Optional[dict]:
        """Get session data as dictionary"""
        session = self._sessions.get(session_id)
        if not session:
            return None
        return {
            "session_id": session.session_id,
            "scam_detected": session.scam_detected,
            "scam_confidence": session.scam_confidence,
            "scam_type": session.scam_type,
            "total_messages": session.total_messages,
            "intelligence": session.intelligence.to_dict(),
            "agent_notes": session.agent_notes,
            "callback_sent": session.callback_sent,
        }
    
    def cleanup_expired(self) -> int:
        """Remove expired sessions"""
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.is_expired]
            for sid in expired:
                del self._sessions[sid]
            return len(expired)


# Global session manager instance
session_manager = SessionManager()
