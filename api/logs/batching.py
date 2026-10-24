import sys
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from time import monotonic

class BatchWorker:
    def __init__(self, consume, *, batch_size, flush_interval, queue_size, name, report_dropped):
        self.consume = consume
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue = Queue(maxsize=queue_size)
        self.report_dropped = report_dropped
        self._stopping = Event()
        self._lock = Lock()
        self._dropped = 0
        self._wake = object()
        self._thread = Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def submit(self, item):
        with self._lock:
            if self._stopping.is_set():
                return False
            try:
                self.queue.put_nowait(item)
                return True
            except Full:
                self._dropped += 1
                return False

    def _run(self):
        while not self._stopping.is_set() or not self.queue.empty():
            batch = []
            deadline = monotonic() + self.flush_interval
            while len(batch) < self.batch_size:
                try:
                    if self._stopping.is_set():
                        item = self.queue.get_nowait()
                    else:
                        item = self.queue.get(timeout=max(0, deadline - monotonic()))
                    if item is self._wake:
                        self.queue.task_done()
                        break
                    batch.append(item)
                except Empty:
                    break
            try:
                if batch:
                    self.consume(batch)
                with self._lock:
                    dropped, self._dropped = self._dropped, 0
                if dropped:
                    self.report_dropped(dropped)
            except Exception as exc:
                sys.stderr.write(f"{self._thread.name}: failed to persist {len(batch)} records: {exc}\n")
            finally:
                for _ in batch:
                    self.queue.task_done()

    def flush(self):
        self.queue.put(self._wake)
        self.queue.join()

    def stop(self):
        with self._lock:
            self._stopping.set()
            try:
                self.queue.put_nowait(self._wake)
            except Full:
                pass
        self._thread.join()
