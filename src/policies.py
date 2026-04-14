"""
Policy engine for mordomo-vault.
Evaluates whether a secret.get request should be granted based on the
stored policies for that secret_key.
"""
import json
import hashlib
from dataclasses import dataclass
from typing import Optional

from src.db import get_policies


@dataclass
class AuthRequest:
    secret_key: str
    requester_module: str
    auth_mode: str          # 'voice' | 'service'
    person_id: Optional[str] = None
    confidence: Optional[float] = None
    module_token: Optional[str] = None


@dataclass
class PolicyResult:
    granted: bool
    reason: Optional[str] = None  # denial reason if not granted


def evaluate(req: AuthRequest) -> PolicyResult:
    """
    Evaluate all enabled policies for req.secret_key.
    Returns granted=True if at least one policy matches and passes.
    """
    policies = get_policies(req.secret_key)

    if not policies:
        return PolicyResult(granted=False, reason="no_policy_defined")

    for policy in policies:
        # Must match auth_mode
        if policy["auth_mode"] != req.auth_mode:
            continue

        allowed_modules: list[str] = json.loads(policy["allowed_modules"])
        if req.requester_module not in allowed_modules:
            continue

        if req.auth_mode == "voice":
            result = _check_voice(req, policy)
        else:
            result = _check_service(req, policy)

        if result.granted:
            return result

    # No policy matched or all denied
    return PolicyResult(granted=False, reason="no_matching_policy")


def _check_voice(req: AuthRequest, policy) -> PolicyResult:
    if req.person_id is None or req.confidence is None:
        return PolicyResult(granted=False, reason="missing_voice_context")

    min_conf = policy["min_confidence"]
    if min_conf is not None and req.confidence < min_conf:
        return PolicyResult(
            granted=False,
            reason=f"confidence_too_low:{req.confidence:.2f}<{min_conf}"
        )

    allowed_persons_raw = policy["allowed_person_ids"]
    if allowed_persons_raw:
        allowed_persons: list[str] = json.loads(allowed_persons_raw)
        if req.person_id not in allowed_persons:
            return PolicyResult(granted=False, reason="person_not_allowed")

    return PolicyResult(granted=True)


def _check_service(req: AuthRequest, policy) -> PolicyResult:
    if req.module_token is None:
        return PolicyResult(granted=False, reason="missing_module_token")

    stored_hash = policy["module_token_hash"]
    if not stored_hash:
        return PolicyResult(granted=False, reason="token_not_configured")

    provided_hash = hashlib.sha256(req.module_token.encode()).hexdigest()
    if provided_hash != stored_hash:
        return PolicyResult(granted=False, reason="token_invalid")

    return PolicyResult(granted=True)
