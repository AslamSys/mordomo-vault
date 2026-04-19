from fastapi import FastAPI, Header, HTTPException, Request
from src.db import get_secret_raw, write_audit
from src.policies import AuthRequest, evaluate
from src.crypto import decrypt
from src.config import VAULT_MASTER_KEY, SUBJECT_AUDIT
import json
import logging
import datetime

logger = logging.getLogger(__name__)

app = FastAPI(title="Mordomo Vault API")

def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

@app.get("/v1/secret/data/{path:path}")
async def get_secret(path: str, x_vault_token: str = Header(None)):
    """
    HashiCorp Vault-like endpoint for secret retrieval.
    Example: GET /v1/secret/data/mordomo/people/security
    """
    # For now, we use module_token as the X-Vault-Token
    requester_module = "http-client" # We could improve this by mapping tokens to modules
    
    req = AuthRequest(
        secret_key=path,
        requester_module=requester_module,
        auth_mode="token",
        module_token=x_vault_token
    )

    result = evaluate(req)

    # Audit write
    write_audit(
        secret_key=path,
        requester_module=requester_module,
        auth_mode="token",
        granted=result.granted,
        denial_reason=result.reason
    )

    if not result.granted:
        raise HTTPException(status_code=403, detail=result.reason)

    row = get_secret_raw(path)
    if not row:
        raise HTTPException(status_code=404, detail="Secret not found")

    try:
        plaintext = decrypt(bytes(row["nonce"]), bytes(row["encrypted_value"]), VAULT_MASTER_KEY)
        
        # Return in HashiCorp format to match People's config.py
        return {
            "data": {
                "data": json.loads(plaintext) if plaintext.startswith("{") else {"value": plaintext, "master_key": plaintext}
            }
        }
    except Exception as e:
        logger.error(f"Decryption failed for {path}: {e}")
        raise HTTPException(status_code=500, detail="Internal decryption error")

from src.db import get_secret_raw, write_audit, upsert_secret, get_all_secrets_raw
from src.crypto import encrypt, decrypt
from src.config import VAULT_MASTER_KEY

@app.get("/get_all")
async def get_all():
    """Retrieve and decrypt all secrets (for dashboard inventory)."""
    try:
        rows = get_all_secrets_raw()
        results = {}
        for row in rows:
            try:
                plaintext = decrypt(bytes(row["nonce"]), bytes(row["encrypted_value"]), VAULT_MASTER_KEY)
                results[row["secret_key"]] = plaintext
            except:
                results[row["secret_key"]] = "[[ERROR: DECRYPTION FAILED]]"
        return results
    except Exception as e:
        logger.error(f"Failed to decrypt all secrets: {e}")
        return {}

@app.post("/set")
async def set_key(request: Request):
    """Encrypt and store a secret in the vault."""
    try:
        data = await request.json()
        key = data.get("key")
        value = data.get("value")
        description = data.get("description", "")
        
        if not key or not value:
            raise HTTPException(status_code=400, detail="Missing key or value")
            
        nonce, ciphertext = encrypt(value, VAULT_MASTER_KEY)
        upsert_secret(key, nonce, ciphertext, description)
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Failed to set secret: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok", "service": "mordomo-vault-api"}
