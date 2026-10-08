# X-API-Key check

import secrets
from fastapi import Header, HTTPException
from .config import API_KEY

def require_key(x_api_key: str = Header(default="")):
    if not API_KEY:
        # raise HTTPException(status_code=401, detail="Invalid API key")
        return  # no key configured -> open (dev only; keep uvicorn on 127.0.0.1)
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")