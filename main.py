import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Query
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(title="Minimal OAuth Broker")

# GPT Action OAuth settings:
# authorization_url = http://localhost:8000/oauth/authorize
# token_url = http://localhost:8000/oauth/token

# Auth0 setup (env-overridable)
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN") or os.getenv(
    "OKTA_DOMAIN", "https://dev-anhyvdf7hdpo4nwf.us.auth0.com"
)
OKTA_BASE = OKTA_DOMAIN.rstrip("/")
OKTA_AUTHORIZE_URL = f"{OKTA_BASE}/v1/authorize"
OKTA_TOKEN_URL = f"{OKTA_BASE}/v1/token"

# Broker callback setup (env-overridable)
BROKER_BASE = os.getenv("BROKER_BASE", "http://localhost:8000")
BROKER_CALLBACK = f"{BROKER_BASE}/oauth/callback"

# Required credentials from environment
OKTA_CLIENT_ID = os.getenv("OKTA_CLIENT_ID") or os.getenv("OKTA_CLIENT_ID")
OKTA_CLIENT_SECRET = os.getenv("OKTA_CLIENT_SECRET") or os.getenv("OKTA_CLIENT_SECRET")

# In-memory stores (prototype only)
state_store: dict[str, dict[str, str]] = {}
token_store: dict[str, dict] = {}
bearer_scheme = HTTPBearer(auto_error=False)


def require_bearer_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> HTTPAuthorizationCredentials:
    # Minimal protection: only require a Bearer token to be present.
    if not credentials or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        print("[protected] unauthorized request", flush=True)
        raise HTTPException(status_code=401, detail="Unauthorized")
    print(f"[protected] bearer token received={credentials.credentials[:8]}...", flush=True)
    return credentials.credentials


@app.get("/oauth/authorize")
async def oauth_authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: str = Query(...),
    scope: str = Query("openid profile email"),
):
    print(
        f"[authorize] start response_type={response_type} state={state[:8]}... redirect_uri={redirect_uri}",
        flush=True,
    )

    # Very basic check to keep flow shape consistent.
    if response_type != "code":
        print("[authorize] invalid response_type", flush=True)
        raise HTTPException(status_code=400, detail="response_type must be code")

    if not OKTA_CLIENT_ID or not OKTA_CLIENT_SECRET:
        print("[authorize] missing OKTA_CLIENT_ID/OKTA_CLIENT_SECRET", flush=True)
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
    print(f"[authorize] stored broker_state={broker_state[:8]}...", flush=True)

    # Redirect to Auth0 using the broker callback (not the ChatGPT callback).
    auth0_query = urlencode(
        {
            "response_type": "code",
            "client_id": OKTA_CLIENT_ID,
            "redirect_uri": BROKER_CALLBACK,
            "scope": "openid profile email",
            "state": broker_state,
        }
    )
    print("[authorize] redirecting to upstream authorize endpoint", flush=True)
    return RedirectResponse(url=f"{OKTA_AUTHORIZE_URL}?{auth0_query}", status_code=302)


@app.get("/oauth/callback")
async def oauth_callback(code: str = Query(...), state: str = Query(...)):
    print(f"[callback] start state={state[:8]}... code={code[:8]}...", flush=True)
    if state not in state_store:
        print("[callback] invalid or expired state", flush=True)
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    # Read and remove one-time authorize state.
    authorize_data = state_store.pop(state)
    chatgpt_redirect_uri = authorize_data["chatgpt_redirect_uri"]
    chatgpt_state = authorize_data["chatgpt_state"]
    print("[callback] state matched, exchanging code for token", flush=True)

    # Exchange Auth0 auth code for tokens.
    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": BROKER_CALLBACK,
        "client_id": OKTA_CLIENT_ID,
        "client_secret": OKTA_CLIENT_SECRET,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_resp = await client.post(
            OKTA_TOKEN_URL,
            data=form_data,
            headers={"Accept": "application/json"},
        )
    print(f"[callback] token exchange status={token_resp.status_code}", flush=True)

    if token_resp.status_code != 200:
        print(f"[callback] token exchange failed body={token_resp.text}", flush=True)
        raise HTTPException(status_code=400, detail=f"Auth0 token exchange failed: {token_resp.text}")

    auth0_token_json = token_resp.json()

    # Create one-time broker code that ChatGPT will exchange at /oauth/token.
    broker_code = secrets.token_urlsafe(24)
    token_store[broker_code] = auth0_token_json
    print(f"[callback] stored broker_code={broker_code[:8]}...", flush=True)

    redirect_query = urlencode({"code": broker_code, "state": chatgpt_state})
    print("[callback] redirecting back to ChatGPT callback", flush=True)
    return RedirectResponse(url=f"{chatgpt_redirect_uri}?{redirect_query}", status_code=302)


@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
):
    print(f"[token] start grant_type={grant_type} code={code[:8]}...", flush=True)

    # Keep this endpoint minimal: require authorization_code and known one-time code.
    if grant_type != "authorization_code":
        print("[token] invalid grant_type", flush=True)
        raise HTTPException(status_code=400, detail="grant_type must be authorization_code")

    if code not in token_store:
        print("[token] invalid or already used code", flush=True)
        raise HTTPException(status_code=400, detail="Invalid or already used code")

    # Consume one-time code and return Auth0 access token directly.
    auth0_token_json = token_store.pop(code)
    access_token = auth0_token_json.get("access_token")
    raw_expires_in = auth0_token_json.get("expires_in", 3600)
    expires_in = int(raw_expires_in) if str(raw_expires_in).isdigit() else 3600

    if not access_token:
        print("[token] upstream response missing access_token", flush=True)
        raise HTTPException(status_code=400, detail="No access_token found in Auth0 response")

    print(f"[token] success access_token={access_token[:8]}... expires_in={expires_in}", flush=True)

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }


@app.get("/protected")
async def protected_endpoint(token: str = Depends(require_bearer_token)):
    return {
        "message": "Authorized request",
        "token_received": True,
        "token": token,
    }

