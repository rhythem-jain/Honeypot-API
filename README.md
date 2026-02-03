# 🎯 Agentic Honeypot API

AI-powered scam detection and intelligence extraction system for the GUVI Hackathon.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

## 🚀 Features

- **Scam Detection**: Identifies scam messages using pattern matching
- **AI Engagement**: Uses Google Gemini to engage scammers as a naive victim
- **Intelligence Extraction**: Extracts UPI IDs, bank accounts, phone numbers, phishing links
- **GUVI Callback**: Automatically reports intelligence to evaluation endpoint

## 📋 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and add your keys:

```bash
cp .env.example .env
```

Edit `.env`:
```
GEMINI_API_KEY=your_gemini_api_key_here
API_KEY=your-secret-api-key
```

### 3. Run Locally

```bash
python main.py
```

Server starts at http://localhost:8000

### 4. Test the API

```bash
# Health check
curl http://localhost:8000/

# Test honeypot endpoint
curl -X POST http://localhost:8000/api/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret-api-key" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "Your bank account is blocked! Share UPI ID immediately.",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": []
  }'
```

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/health` | Health check |
| GET | `/api/honeypot` | API validation (for GUVI tester) |
| POST | `/api/honeypot` | Main honeypot endpoint |
| GET | `/session/{id}` | Get session info (debug) |
| POST | `/report/{id}` | Force send GUVI callback |

## 📤 Deploy to Render

1. Push code to GitHub
2. Go to [render.com](https://render.com) and create new Web Service
3. Connect your GitHub repository
4. Configure:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Set environment variables:
   - `GEMINI_API_KEY` - Your Google AI API key
   - `API_KEY` - Your chosen authentication key
6. Deploy!

## 📝 GUVI Submission

After deployment, submit these details to GUVI:
- **Deployed URL**: `https://your-app.onrender.com/api/honeypot`
- **API KEY**: The value you set for `API_KEY` environment variable

## 📝 Response Format

```json
{
  "status": "success",
  "reply": "Oh dear, what has happened? Please help me!"
}
```

## 🔒 Authentication

All endpoints require `x-api-key` header with your secret API key.

## 📊 GUVI Callback

When scam is detected and sufficient intelligence is extracted, the system automatically sends a callback to:

```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

Payload:
```json
{
  "sessionId": "abc123",
  "scamDetected": true,
  "totalMessagesExchanged": 10,
  "extractedIntelligence": {
    "bankAccounts": ["1234567890"],
    "upiIds": ["scammer@ybl"],
    "phishingLinks": ["http://fake-link.com"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "blocked", "verify"]
  },
  "agentNotes": "Scammer used urgency tactics"
}
```

## 🛠️ Tech Stack

- **FastAPI** - Web framework
- **Google Gemini** - AI responses (FREE tier)
- **Pydantic** - Data validation
- **HTTPX** - Async HTTP client

## 📄 License

MIT
