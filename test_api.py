"""
Tests for the Honeypot API — validates GUVI evaluation compliance.

Checks:
1. Response schema: reply is an object with message, confidence, scamDetected, etc.
2. Content-Type is always application/json
3. Valid scam messages return correct detection results
4. Malformed payloads return HTTP 400
5. Missing API key returns HTTP 401/422
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
    """Assert the response matches GUVI's expected contract."""
    assert "status" in data, "Missing 'status' field"
    assert "reply" in data, "Missing 'reply' field"

    reply = data["reply"]
    assert isinstance(reply, dict), f"'reply' must be an object, got {type(reply).__name__}"
    assert "message" in reply, "reply missing 'message'"
    assert "confidence" in reply, "reply missing 'confidence'"
    assert "scamDetected" in reply, "reply missing 'scamDetected'"
    assert "scamType" in reply, "reply missing 'scamType'"
    assert "extractedIntelligence" in reply, "reply missing 'extractedIntelligence'"
    assert "engagementPhase" in reply, "reply missing 'engagementPhase'"

    assert isinstance(reply["message"], str)
    assert isinstance(reply["confidence"], (int, float))
    assert isinstance(reply["scamDetected"], bool)
    assert isinstance(reply["scamType"], str)
    assert isinstance(reply["extractedIntelligence"], dict)


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
        reply = data["reply"]
        assert reply["scamDetected"] is True
        assert reply["confidence"] > 0
        assert len(reply["message"]) > 0

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

    def test_reply_is_not_string(self, client):
        """CRITICAL: reply must NEVER be a plain string."""
        payload = {
            "sessionId": "test-session-schema",
            "message": {"sender": "scammer", "text": "Send money now!"},
            "conversationHistory": []
        }
        resp = client.post("/api/honeypot", json=payload, headers=HEADERS)
        data = resp.json()
        assert not isinstance(data.get("reply"), str), \
            "FAIL: 'reply' is a plain string — GUVI requires it to be an object!"


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
