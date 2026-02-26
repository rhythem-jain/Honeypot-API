"""
Tests for the Honeypot API — validates GUVI evaluation compliance.

Checks:
1. Response schema: reply is a plain string, extra fields at top level
2. Content-Type is always application/json
3. Valid scam messages return correct detection results
4. Malformed payloads return HTTP 400
5. Missing API key returns HTTP 401/422
6. Intelligence extraction works (phone numbers, bank accounts, UPI IDs)
"""

import pytest
from fastapi.testclient import TestClient

from main import app


# --- Fixtures ---

@pytest.fixture
def client():
    return TestClient(app)


API_KEY = "your-secret-api-key"  # Must match .env / config default
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}


# --- Helper ---

def assert_valid_reply_schema(data: dict):
    """Assert the response matches GUVI's expected contract (flat format)."""
    assert "status" in data, "Missing 'status' field"
    assert "reply" in data, "Missing 'reply' field"

    # reply must be a PLAIN STRING (not an object)
    assert isinstance(data["reply"], str), f"'reply' must be a string, got {type(data['reply']).__name__}"
    assert len(data["reply"]) > 0, "reply must not be empty"

    # Extra fields at top level
    assert "confidence" in data, "Missing 'confidence' field"
    assert "scamDetected" in data, "Missing 'scamDetected' field"
    assert "scamType" in data, "Missing 'scamType' field"
    assert "extractedIntelligence" in data, "Missing 'extractedIntelligence' field"
    assert "engagementPhase" in data, "Missing 'engagementPhase' field"

    assert isinstance(data["confidence"], (int, float))
    assert isinstance(data["scamDetected"], bool)
    assert isinstance(data["scamType"], str)
    assert isinstance(data["extractedIntelligence"], dict)


# --- Tests ---

class TestHealthEndpoints:
    def test_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "online"

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_get_honeypot(self, client):
        resp = client.get("/api/honeypot", headers=HEADERS)
        assert resp.status_code == 200


class TestResponseSchema:
    """Core tests: every POST to /api/honeypot MUST return a compliant schema."""

    def test_valid_scam_message(self, client):
        """A typical scam message should return structured reply with scam detection."""
        payload = {
            "sessionId": "test-session-001",
            "message": {
                "sender": "scammer",
                "text": "Your bank account has been blocked! Send OTP immediately to unblock. UPI: scammer@ybl"
            },
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

        data = resp.json()
        assert_valid_reply_schema(data)
        assert data["status"] == "success"

        # This message has clear scam signals
        assert data["scamDetected"] is True
        assert data["confidence"] > 0
        assert len(data["reply"]) > 0

    def test_normal_message(self, client):
        """A non-scam message should still return the correct schema."""
        payload = {
            "sessionId": "test-session-002",
            "message": {
                "sender": "scammer",
                "text": "Hello, how are you doing today?"
            },
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

        data = resp.json()
        assert_valid_reply_schema(data)

    def test_empty_post_body(self, client):
        """Empty POST should return 200 with valid schema (not crash)."""
        resp = client.post(
            "/api/honeypot",
            content="",
            headers={"x-api-key": API_KEY}
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

        data = resp.json()
        assert_valid_reply_schema(data)

    def test_reply_is_string(self, client):
        """CRITICAL: reply MUST be a plain string (not an object)."""
        payload = {
            "sessionId": "test-session-schema",
            "message": {"sender": "scammer", "text": "Send money now!"},
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        data = resp.json()
        assert isinstance(data.get("reply"), str), \
            "FAIL: 'reply' must be a plain string for GUVI!"


class TestInputValidation:
    """Malformed payloads should return HTTP 400, not silent 200."""

    def test_missing_session_id(self, client):
        """Missing sessionId should return 400."""
        payload = {
            "message": {"sender": "scammer", "text": "Hello"}
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 400
        assert resp.headers["content-type"] == "application/json"

    def test_missing_message(self, client):
        """Missing message field should return 400."""
        payload = {"sessionId": "test-bad"}
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 400

    def test_malformed_message(self, client):
        """message as a string instead of object should return 400."""
        payload = {
            "sessionId": "test-bad-2",
            "message": "this is a string, not an object"
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 400

    def test_timestamp_as_integer(self, client):
        """timestamp sent as integer should be accepted (GUVI sends this)."""
        payload = {
            "sessionId": "test-timestamp-int",
            "message": {
                "sender": "scammer",
                "text": "Send money now!",
                "timestamp": 1772102249669
            },
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 200

    def test_conversation_history_with_dict_text(self, client):
        """GUVI sends reply objects back as text in conversationHistory."""
        payload = {
            "sessionId": "test-dict-text",
            "message": {"sender": "scammer", "text": "Send money!"},
            "conversationHistory": [
                {"sender": "scammer", "text": "Your account is blocked!"},
                {"sender": "user", "text": {"message": "Oh no!", "confidence": 0.5, "scamDetected": True}},
            ]
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert_valid_reply_schema(data)


class TestAuthentication:
    def test_missing_api_key(self, client):
        """Missing API key should fail."""
        payload = {
            "sessionId": "test-auth",
            "message": {"sender": "scammer", "text": "Hello"}
        }
        resp = client.post("/api/honeypot", json=payload)
        assert resp.status_code == 400  # Our custom handler returns 400 for validation errors

    def test_wrong_api_key(self, client):
        """Wrong API key should return 401."""
        payload = {
            "sessionId": "test-auth-2",
            "message": {"sender": "scammer", "text": "Hello"}
        }
        resp = client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": "wrong-key"}
        )
        assert resp.status_code == 401


class TestContentType:
    """All responses must be application/json."""

    def test_success_content_type(self, client):
        payload = {
            "sessionId": "test-ct",
            "message": {"sender": "scammer", "text": "Your account blocked!"}
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        assert "application/json" in resp.headers["content-type"]

    def test_error_content_type(self, client):
        resp = client.post("/api/honeypot", json={"bad": "data"}, headers=HEADERS)
        assert "application/json" in resp.headers["content-type"]


class TestIntelligenceExtraction:
    """Verify intelligence extraction works correctly."""

    def test_extracts_upi_id(self, client):
        """UPI IDs should be detected."""
        payload = {
            "sessionId": "test-intel-upi",
            "message": {
                "sender": "scammer",
                "text": "Send money to scammer@ybl immediately!"
            },
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        data = resp.json()
        intel = data.get("extractedIntelligence", {})
        assert "scammer@ybl" in intel.get("upiIds", [])

    def test_extracts_phone_with_dashes(self, client):
        """Phone numbers with dashes should be detected."""
        payload = {
            "sessionId": "test-intel-phone",
            "message": {
                "sender": "scammer",
                "text": "Call me at +91-9876543210 for verification."
            },
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        data = resp.json()
        intel = data.get("extractedIntelligence", {})
        assert "+919876543210" in intel.get("phoneNumbers", [])

    def test_extracts_bank_account(self, client):
        """16-digit bank account numbers near context keywords should be detected."""
        payload = {
            "sessionId": "test-intel-bank",
            "message": {
                "sender": "scammer",
                "text": "Transfer to account number 1234567890123456 now!"
            },
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        data = resp.json()
        intel = data.get("extractedIntelligence", {})
        assert "1234567890123456" in intel.get("bankAccounts", [])
