"""
NATS message handlers for mordomo-vault.
"""
import json
import datetime
import logging

from nats.aio.msg import Msg

from src.config import SUBJECT_AUDIT, VAULT_MASTER_KEY
from src.crypto import decrypt
from src.db import get_secret_raw, write_audit
from src.policies import AuthRequest, evaluate

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


async def handle_secret_get(msg: Msg) -> None:
    """
    Subject: mordomo.vault.secret.get
    Request/reply — caller expects a NATS reply.
    """
    nc = msg._client  # nats.aio.client.Client attached by main

    try:
        data = json.loads(msg.data.decode())
    except Exception:
        if msg.reply:
            await nc.publish(msg.reply, json.dumps({"error": "invalid_json"}).encode())
        return

    secret_key       = data.get("secret_key", "")
    requester_module = data.get("requester_module", "")
    auth_mode        = data.get("auth_mode", "")

    req = AuthRequest(
        secret_key       = secret_key,
        requester_module = requester_module,
        auth_mode        = auth_mode,
        person_id        = data.get("person_id"),
        confidence       = data.get("confidence"),
        module_token     = data.get("module_token"),
    )

    result = evaluate(req)

    # Audit log (sync — fast SQLite write)
    write_audit(
        secret_key       = secret_key,
        requester_module = requester_module,
        auth_mode        = auth_mode,
        granted          = result.granted,
        person_id        = req.person_id,
        confidence       = req.confidence,
        denial_reason    = result.reason,
    )

    # Publish audit event
    audit_payload = {
        "secret_key":       secret_key,
        "requester_module": requester_module,
        "auth_mode":        auth_mode,
        "granted":          result.granted,
        "person_id":        req.person_id,
        "confidence":       req.confidence,
        "denial_reason":    result.reason,
        "timestamp":        _now_iso(),
    }
    await nc.publish(SUBJECT_AUDIT, json.dumps(audit_payload).encode())

    if not msg.reply:
        return

    if not result.granted:
        logger.warning(
            "DENIED secret=%s module=%s reason=%s",
            secret_key, requester_module, result.reason
        )
        await nc.publish(
            msg.reply,
            json.dumps({"error": "unauthorized", "reason": result.reason}).encode()
        )
        return

    # Fetch and decrypt
    row = get_secret_raw(secret_key)
    if row is None:
        await nc.publish(
            msg.reply,
            json.dumps({"error": "secret_not_found"}).encode()
        )
        return

    try:
        plaintext = decrypt(bytes(row["nonce"]), bytes(row["encrypted_value"]), VAULT_MASTER_KEY)
    except Exception as e:
        logger.error("Decryption failed for %s: %s", secret_key, e)
        await nc.publish(
            msg.reply,
            json.dumps({"error": "decryption_failed"}).encode()
        )
        return

    logger.info("GRANTED secret=%s module=%s", secret_key, requester_module)
    await nc.publish(msg.reply, json.dumps({"value": plaintext}).encode())


async def handle_policy_reload(msg: Msg) -> None:
    """
    Subject: mordomo.vault.policy.reload
    Policies are loaded fresh from SQLite on each request — no in-memory cache —
    so this handler just ACKs to confirm the service is alive.
    """
    nc = msg._client
    logger.info("policy.reload received — policies are always read fresh from DB")
    if msg.reply:
        await nc.publish(msg.reply, json.dumps({"status": "ok"}).encode())
