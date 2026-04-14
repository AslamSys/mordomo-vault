"""
mordomo-vault — entrypoint.
"""
import asyncio
import logging
import signal

import nats

from src.config import NATS_URL, SUBJECT_SECRET_GET, SUBJECT_POLICY_RELOAD
from src.db import init_db
from src.handlers import handle_secret_get, handle_policy_reload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mordomo-vault")

_shutdown = asyncio.Event()


def _handle_signal(sig):
    logger.info("Signal %s received — shutting down", sig.name)
    _shutdown.set()


async def _subscribe_with_client(nc, subject, handler):
    """Wrapper so handlers can access the NC client via msg._client."""
    async def _wrapper(msg):
        msg._client = nc
        await handler(msg)
    return await nc.subscribe(subject, cb=_wrapper)


async def run() -> None:
    init_db()
    logger.info("Database initialised at %s", __import__("src.config", fromlist=["VAULT_DB_PATH"]).VAULT_DB_PATH)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: _handle_signal(s))

    nc = None
    while not _shutdown.is_set():
        try:
            nc = await nats.connect(
                NATS_URL,
                name="mordomo-vault",
                reconnect_time_wait=2,
                max_reconnect_attempts=-1,
            )
            logger.info("Connected to NATS at %s", NATS_URL)

            await _subscribe_with_client(nc, SUBJECT_SECRET_GET, handle_secret_get)
            await _subscribe_with_client(nc, SUBJECT_POLICY_RELOAD, handle_policy_reload)

            logger.info("Subscribed — vault ready")
            await _shutdown.wait()

        except Exception as exc:
            logger.error("Connection error: %s — retrying in 5s", exc)
            await asyncio.sleep(5)
        finally:
            if nc and not nc.is_closed:
                await nc.drain()

    logger.info("Vault stopped")


if __name__ == "__main__":
    asyncio.run(run())
