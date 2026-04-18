import asyncio
import logging
import signal
import nats
import uvicorn
from src.config import NATS_URL, SUBJECT_SECRET_GET, SUBJECT_POLICY_RELOAD
from src.db import init_db
from src.handlers import handle_secret_get, handle_policy_reload
from src.api import app

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
    async def _wrapper(msg):
        msg._client = nc
        await handler(msg)
    return await nc.subscribe(subject, cb=_wrapper)

async def run_nats():
    """Background task for NATS."""
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
        logger.info("NATS handlers ready")
        return nc
    except Exception as e:
        logger.error(f"Failed to connect to NATS: {e}")
        return None

async def main() -> None:
    init_db()
    
    # Start NATS
    nc = await run_nats()

    # Start FastAPI
    config = uvicorn.Config(app, host="0.0.0.0", port=8200, log_level="info")
    server = uvicorn.Server(config)

    # Handle signals
    def _stop_server(*_):
        _shutdown.set()
        server.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop_server)

    logger.info("Vault ready (Web on :8200 + NATS)")
    await server.serve()

    if nc:
        await nc.drain()
    logger.info("Vault stopped")

if __name__ == "__main__":
    asyncio.run(main())
