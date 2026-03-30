"""
threaded_server.py — Per-client worker thread pool for ReliableUDPServer


"""

import threading
import queue
import logging

log = logging.getLogger(__name__)


class ThreadedServerWrapper:
    def __init__(self, server):
        self.server         = server
        self.client_queues  = {}
        self.client_threads = {}
        self.lock           = threading.Lock()

        # FIX: Give the server a back-reference so _handle_bye can trigger
        # cleanup after it removes the session from self.sessions.
        self.server._threaded_wrapper = self

    # ── Worker ────────────────────────────────────────────────────────────────

    def _client_worker(self, addr, q: queue.Queue):
        """Drain packets for one client until a None sentinel is received."""
        while True:
            raw = q.get()
            if raw is None:   # sentinel: shut down this worker
                break
            try:
                self.server._process_packet(raw, addr)
            except Exception as e:
                log.error(f"Unhandled error processing packet from {addr}: {e}")

    # ── Public: called by server after BYE handling ──────────────────────────

    def cleanup_client(self, addr):
        """
        Send a sentinel to the client's worker thread and remove all
        bookkeeping for that address.

        FIX: Without this, every disconnected client leaves a running daemon
             thread and a queue in memory for the lifetime of the server.
        """
        with self.lock:
            q = self.client_queues.pop(addr, None)
            t = self.client_threads.pop(addr, None)

        if q is not None:
            q.put(None)   # wake the worker so it can exit cleanly
        if t is not None:
            t.join(timeout=2.0)
            log.debug(f"Worker thread for {addr} cleaned up")

    # ── Main receive loop ────────────────────────────────────────────────────

    def run(self):
        sock = self.server.sock
        log.info("Threaded wrapper active…")

        while True:
            try:
                raw, addr = sock.recvfrom(65535)
            except KeyboardInterrupt:
                log.info("Shutting down.")
                self._shutdown_all()
                break

            with self.lock:
                if addr not in self.client_queues:
                    q = queue.Queue()
                    self.client_queues[addr] = q
                    t = threading.Thread(
                        target=self._client_worker,
                        args=(addr, q),
                        daemon=True
                    )
                    self.client_threads[addr] = t
                    t.start()

            self.client_queues[addr].put(raw)

    def _shutdown_all(self):
        """Send shutdown sentinel to all live workers."""
        with self.lock:
            addrs = list(self.client_queues.keys())
        for addr in addrs:
            self.cleanup_client(addr)
