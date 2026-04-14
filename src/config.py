import os
import binascii

NATS_URL: str = os.getenv("NATS_URL", "nats://nats:4222")
VAULT_DB_PATH: str = os.getenv("VAULT_DB_PATH", "/data/vault.db")

_master_key_hex = os.getenv("VAULT_MASTER_KEY", "")
if not _master_key_hex or len(_master_key_hex) != 64:
    raise RuntimeError(
        "VAULT_MASTER_KEY must be set to a 64-char hex string (32 bytes). "
        "Generate with: python -c \"import os,binascii; print(binascii.hexlify(os.urandom(32)).decode())\""
    )
VAULT_MASTER_KEY: bytes = binascii.unhexlify(_master_key_hex)

# NATS subjects
SUBJECT_SECRET_GET = "mordomo.vault.secret.get"
SUBJECT_POLICY_RELOAD = "mordomo.vault.policy.reload"
SUBJECT_AUDIT = "mordomo.vault.audit"
