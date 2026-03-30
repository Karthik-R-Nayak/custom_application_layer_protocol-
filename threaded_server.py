import threading
import queue


class ThreadedServerWrapper:
    def __init__(self, server):
        self.server = server
        self.client_queues = {}
        self.client_threads = {}
        self.lock = threading.Lock()

    def _client_worker(self, addr, q):
        while True:
            raw = q.get()
            if raw is None:
                break
            self.server._process_packet(raw, addr)

    def run(self):
        sock = self.server.sock

        print("Threaded wrapper active...")

        while True:
            try:
                raw, addr = sock.recvfrom(65535)
            except KeyboardInterrupt:
                print("Shutting down.")
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
