"""
vault_cli.py — Bootstrap and management CLI for mordomo-vault.

Usage:
  # Store a new secret
  python vault_cli.py set-secret --key asaas_api_key --value "sk_live_..." --desc "ASAAS payment key"

  # Add voice policy
  python vault_cli.py add-policy --key asaas_api_key --mode voice \
      --modules mordomo-financas-pix --persons owner --min-confidence 0.95

  # Add service policy and generate a module token
  python vault_cli.py add-policy --key binance_api_key --mode service \
      --modules investimentos-trading-bot

  python vault_cli.py issue-token --module investimentos-trading-bot
  # → prints VAULT_MODULE_TOKEN=vtk_... (add to the module's .env)

  python vault_cli.py revoke-token --module investimentos-trading-bot

  # List secrets
  python vault_cli.py list

  # Delete a secret (and its policies)
  python vault_cli.py delete-secret --key asaas_api_key
"""
import argparse
import binascii
import hashlib
import json
import os
import secrets
import sys

# Allow running from repo root
sys.path.insert(0, os.path.dirname(__file__))

from src.config import VAULT_MASTER_KEY, VAULT_DB_PATH
from src.crypto import encrypt
from src.db import (
    init_db,
    upsert_secret,
    delete_secret,
    upsert_policy,
    issue_token_for_module,
    get_policies,
    _connect,
)


def cmd_set_secret(args):
    nonce, ciphertext = encrypt(args.value, VAULT_MASTER_KEY)
    upsert_secret(args.key, nonce, ciphertext, args.desc or "")
    print(f"✅  Secret '{args.key}' stored.")


def cmd_add_policy(args):
    modules = args.modules.split(",")
    persons = args.persons.split(",") if args.persons else None
    upsert_policy(
        secret_key=args.key,
        auth_mode=args.mode,
        allowed_modules=modules,
        allowed_person_ids=persons,
        min_confidence=args.min_confidence,
        module_token=None,
    )
    print(f"✅  Policy added for '{args.key}' [{args.mode}].")
    if args.mode == "service":
        print("   Run 'issue-token' to assign a module token.")


def cmd_issue_token(args):
    token = "vtk_" + secrets.token_urlsafe(32)
    updated = issue_token_for_module(args.module, token)
    if updated == 0:
        print(
            f"⚠️  No service policies found for module '{args.module}'. "
            "Add a service policy first with 'add-policy --mode service'."
        )
        return
    print(f"✅  Token issued for module '{args.module}':")
    print(f"    VAULT_MODULE_TOKEN={token}")
    print("    Add this to the module's .env — it will NOT be shown again.")


def cmd_revoke_token(args):
    conn = _connect()
    with conn:
        result = conn.execute("""
            UPDATE policies
            SET module_token_hash = NULL, enabled = 0
            WHERE auth_mode = 'service' AND instr(allowed_modules, ?) > 0
        """, (args.module,))
        updated = result.rowcount
    conn.close()
    print(f"✅  Revoked {updated} policy(ies) for module '{args.module}'.")


def cmd_list(args):
    conn = _connect()
    rows = conn.execute(
        "SELECT secret_key, description, created_at, updated_at FROM secrets ORDER BY secret_key"
    ).fetchall()
    conn.close()
    if not rows:
        print("No secrets stored.")
        return
    print(f"{'SECRET KEY':<30} {'DESCRIPTION':<40} {'UPDATED AT'}")
    print("-" * 85)
    for r in rows:
        print(f"{r['secret_key']:<30} {(r['description'] or ''):<40} {r['updated_at']}")


def cmd_delete_secret(args):
    delete_secret(args.key)
    print(f"✅  Secret '{args.key}' deleted (policies cascade-deleted too).")


def main():
    init_db()

    parser = argparse.ArgumentParser(description="mordomo-vault CLI")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("set-secret", help="Store or update a secret")
    p.add_argument("--key", required=True)
    p.add_argument("--value", required=True)
    p.add_argument("--desc", default="")

    p = sub.add_parser("add-policy", help="Add access policy for a secret")
    p.add_argument("--key", required=True)
    p.add_argument("--mode", required=True, choices=["voice", "service"])
    p.add_argument("--modules", required=True, help="Comma-separated module names")
    p.add_argument("--persons", default=None, help="Comma-separated person_ids (voice only)")
    p.add_argument("--min-confidence", type=float, default=None, dest="min_confidence")

    p = sub.add_parser("issue-token", help="Generate a module token (service auth)")
    p.add_argument("--module", required=True)

    p = sub.add_parser("revoke-token", help="Revoke module token and disable policies")
    p.add_argument("--module", required=True)

    sub.add_parser("list", help="List all secrets")

    p = sub.add_parser("delete-secret", help="Delete a secret and its policies")
    p.add_argument("--key", required=True)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    dispatch = {
        "set-secret":    cmd_set_secret,
        "add-policy":    cmd_add_policy,
        "issue-token":   cmd_issue_token,
        "revoke-token":  cmd_revoke_token,
        "list":          cmd_list,
        "delete-secret": cmd_delete_secret,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
