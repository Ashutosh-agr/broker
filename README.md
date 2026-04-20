# Minimal OAuth Broker (FastAPI)

This is a tiny OAuth broker for ChatGPT Custom GPT Actions with Okta.

## What it does

- Receives OAuth authorize call from ChatGPT at `/oauth/authorize`
- Redirects user to Okta `/v1/authorize`
- Receives Okta callback at `/oauth/callback`
- Exchanges Okta code at Okta `/v1/token`
- Stores Okta token response in memory using a one-time random code
- Returns the Okta access token to ChatGPT at `/oauth/token`

No custom JWTs, no DB, no Redis, no extra auth logic.

## Required environment variables

- `OKTA_CLIENT_ID`
- `OKTA_CLIENT_SECRET`

## Optional environment variables

- `OKTA_DOMAIN` (default: `https://dev-anhyvdf7hdpo4nwf.us.auth0.com`)
- `BROKER_BASE` (default: `http://localhost:8000`)

## Install and run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OKTA_CLIENT_ID="your_okta_client_id"
$env:OKTA_CLIENT_SECRET="your_okta_client_secret"
$env:OKTA_DOMAIN="https://your-tenant.example.com"
$env:BROKER_BASE="http://localhost:8000"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## GPT Action OAuth config

- `authorization_url = <BROKER_BASE>/oauth/authorize`
- `token_url = <BROKER_BASE>/oauth/token`

## Notes

- Configure Okta app redirect URI as `<BROKER_BASE>/oauth/callback`
- In-memory storage resets when the server restarts

