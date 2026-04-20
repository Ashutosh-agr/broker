import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import RedirectResponse

app = FastAPI(title="Minimal OAuth Broker")

# GPT Action OAuth settings:
# authorization_url = http://localhost:8000/oauth/authorize
# token_url = http://localhost:8000/oauth/token

# Auth0 setup (env-overridable)
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN") or os.getenv(
    "OKTA_DOMAIN", "https://dev-anhyvdf7hdpo4nwf.us.auth0.com"
)
AUTH0_BASE = AUTH0_DOMAIN.rstrip("/")
AUTH0_AUTHORIZE_URL = f"{AUTH0_BASE}/authorize"
AUTH0_TOKEN_URL = f"{AUTH0_BASE}/oauth/token"

# Broker callback setup (env-overridable)
BROKER_BASE = os.getenv("BROKER_BASE", "http://localhost:8000")
BROKER_CALLBACK = f"{BROKER_BASE}/oauth/callback"

# Required credentials from environment
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID") or os.getenv("OKTA_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET") or os.getenv("OKTA_CLIENT_SECRET")

# In-memory stores (prototype only)
state_store: dict[str, dict[str, str]] = {}
token_store: dict[str, dict] = {}


@app.get("/oauth/authorize")
async def oauth_authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: str = Query(...),
    scope: str = Query("openid profile email"),
):
    # Very basic check to keep flow shape consistent.
    if response_type != "code":
        raise HTTPException(status_code=400, detail="response_type must be code")

    if not AUTH0_CLIENT_ID or not AUTH0_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Missing AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET (or OKTA_CLIENT_ID/OKTA_CLIENT_SECRET)",
        )

    # Save ChatGPT callback details under an internal broker state.
    broker_state = secrets.token_urlsafe(24)
    state_store[broker_state] = {
        "chatgpt_redirect_uri": redirect_uri,
        "chatgpt_state": state,
        "created_at": str(int(time.time())),
    }

    # Redirect to Auth0 using the broker callback (not the ChatGPT callback).
    auth0_query = urlencode(
        {
            "response_type": "code",
            "client_id": AUTH0_CLIENT_ID,
            "redirect_uri": BROKER_CALLBACK,
            "scope": "openid profile email",
            "state": broker_state,
        }
    )
    return RedirectResponse(url=f"{AUTH0_AUTHORIZE_URL}?{auth0_query}", status_code=302)


@app.get("/oauth/callback")
async def oauth_callback(code: str = Query(...), state: str = Query(...)):
    if state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    # Read and remove one-time authorize state.
    authorize_data = state_store.pop(state)
    chatgpt_redirect_uri = authorize_data["chatgpt_redirect_uri"]
    chatgpt_state = authorize_data["chatgpt_state"]

    # Exchange Auth0 auth code for tokens.
    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": BROKER_CALLBACK,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_resp = await client.post(
            AUTH0_TOKEN_URL,
            data=form_data,
            auth=(AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET),
            headers={"Accept": "application/json"},
        )

    if token_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Auth0 token exchange failed: {token_resp.text}")

    auth0_token_json = token_resp.json()

    # Create one-time broker code that ChatGPT will exchange at /oauth/token.
    broker_code = secrets.token_urlsafe(24)
    token_store[broker_code] = auth0_token_json

    redirect_query = urlencode({"code": broker_code, "state": chatgpt_state})
    return RedirectResponse(url=f"{chatgpt_redirect_uri}?{redirect_query}", status_code=302)


@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
):
    # Keep this endpoint minimal: require authorization_code and known one-time code.
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="grant_type must be authorization_code")

    if code not in token_store:
        raise HTTPException(status_code=400, detail="Invalid or already used code")

    # Consume one-time code and return Auth0 access token directly.
    auth0_token_json = token_store.pop(code)
    access_token = auth0_token_json.get("access_token")
    raw_expires_in = auth0_token_json.get("expires_in", 3600)
    expires_in = int(raw_expires_in) if str(raw_expires_in).isdigit() else 3600

    if not access_token:
        raise HTTPException(status_code=400, detail="No access_token found in Auth0 response")

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
