# 🎯 Agentic Honeypot API

AI-powered scam detection and intelligence extraction system for the GUVI Hackathon.

## 🚀 Features

- **Scam Detection**: Identifies scam messages using pattern matching
- **AI Engagement**: Uses Google Gemini to engage scammers as a naive victim
- **Intelligence Extraction**: Extracts UPI IDs, bank accounts, phone numbers, phishing links
- **GUVI Callback**: Automatically reports intelligence to evaluation endpoint

## 📋 Quick Start (Local Development)

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

---

## ☁️ Deploy to Azure App Service (Recommended)

### Prerequisites
- GitHub account with your code pushed
- GitHub Student Developer Pack (for free $100 Azure credits)

### Step 1: Activate Azure for Students

1. Go to [azure.microsoft.com/free/students](https://azure.microsoft.com/free/students)
2. Click **"Start free"**
3. Sign in with your school email OR link your GitHub Student account
4. ✅ **No credit card required!**

### Step 2: Create Web App

1. Go to [portal.azure.com](https://portal.azure.com)
2. Click **"Create a resource"** (+ icon)
3. Search for **"Web App"** and click **Create**

### Step 3: Configure Basic Settings

| Setting | Value |
|---------|-------|
| **Subscription** | Azure for Students |
| **Resource Group** | Click "Create new" → `honeypot-rg` |
| **Name** | `honeypot-api-yourname` (must be globally unique) |
| **Publish** | Code |
| **Runtime stack** | Python 3.11 |
| **Operating System** | Linux |
| **Region** | Central India (or nearest to you) |

### Step 4: Choose Pricing Plan

1. Click **"Create new"** under Linux Plan
2. Name it: `honeypot-plan`
3. Click **"Change size"** → Select **B1 (Basic)** tier
   - Cost: ~$13/month (covered by your $100 credits)
   - ✅ No cold start delays!

4. Click **"Review + create"** → **"Create"**
5. Wait 1-2 minutes for deployment

### Step 5: Connect GitHub for Auto-Deploy

1. After creation, go to your Web App
2. In left sidebar, click **"Deployment Center"**
3. Under **Source**, select **GitHub**
4. Click **"Authorize"** and log into GitHub
5. Select:
   - **Organization**: Your GitHub username
   - **Repository**: `Honeypot-API`
   - **Branch**: `main`
6. Click **"Save"**

### Step 6: Configure Startup Command

1. In left sidebar, click **"Configuration"**
2. Click **"General settings"** tab
3. In **"Startup Command"** field, enter:
   ```
   gunicorn --bind=0.0.0.0 --timeout 600 -k uvicorn.workers.UvicornWorker main:app
   ```
4. Click **"Save"** at the top

### Step 7: Set Environment Variables

1. Stay in **"Configuration"** → **"Application settings"** tab
2. Click **"+ New application setting"** and add:

   | Name | Value |
   |------|-------|
   | `GEMINI_API_KEY` | Your Google Gemini API key |
   | `API_KEY` | Your chosen secret key (e.g., `supersecret123`) |
   | `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` |
   | `WEBSITE_RUN_FROM_PACKAGE` | `0` |

3. Click **"Save"** → **"Continue"** to confirm

### Step 8: Restart and Test

1. Click **"Overview"** in left sidebar
2. Click **"Restart"** at the top
3. Wait 2-3 minutes for deployment
4. Click **"Browse"** or visit your URL:
   ```
   https://honeypot-api-yourname.azurewebsites.net
   ```

### Step 9: Verify Deployment

Test your API:
```bash
# Health check
curl https://honeypot-api-yourname.azurewebsites.net/

# Test POST endpoint
curl -X POST https://honeypot-api-yourname.azurewebsites.net/api/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: supersecret123" \
  -d '{"sessionId": "test", "message": {"sender": "scammer", "text": "Hello test", "timestamp": "2026-02-03T10:00:00Z"}, "conversationHistory": []}'
```

---

## 📤 Alternative: Deploy to Render

> ⚠️ **Warning**: Render free tier has 30-60 second cold start delays which may cause GUVI tests to timeout.

1. Push code to GitHub
2. Go to [render.com](https://render.com) and create new Web Service
3. Connect your GitHub repository
4. Configure:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Set environment variables: `GEMINI_API_KEY`, `API_KEY`
6. Deploy!

---

## 📝 GUVI Hackathon Submission

After deployment, submit these details to GUVI:

| Field | Value |
|-------|-------|
| **Deployed URL** | `https://your-app-name.azurewebsites.net/api/honeypot` |
| **API KEY** | The value you set for `API_KEY` environment variable |

> ⚠️ **Important**: Make sure to include `/api/honeypot` at the end of your URL!

---

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
- **Gunicorn** - Production WSGI server (for Azure)

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| 500 Internal Server Error | Check logs in Azure Portal → "Log stream" |
| INVALID_REQUEST_BODY | Ensure URL ends with `/api/honeypot` |
| API Key error | Verify `x-api-key` header matches your `API_KEY` |
| Cold start delays | Use Azure B1 tier (not free tier) |
| Build fails | Check if all dependencies are in `requirements.txt` |

## 📄 License

MIT
