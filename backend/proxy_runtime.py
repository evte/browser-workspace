"""Thread-owned gateway loop used by the synchronous browser lifecycle API."""
import asyncio
import threading
from .proxy_gateway import ProxyGateway
from .direct_gateway import DirectGateway


class GatewayRuntime:
    def __init__(self, proxy, path, on_failure):
        self.loop = asyncio.new_event_loop()
        self.gateway = ProxyGateway(proxy, path, on_failure) if proxy else DirectGateway(path, on_failure)
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        try:
            asyncio.run_coroutine_threadsafe(self.gateway.start(), self.loop).result(timeout=20)
        except Exception:
            self.close()
            raise

    def close(self):
        if not self.loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(self.gateway.close(), self.loop).result(timeout=10)
            finally:
                self.loop.call_soon_threadsafe(self.loop.stop)
                self.thread.join(timeout=12)
                if not self.thread.is_alive():
                    self.loop.close()
