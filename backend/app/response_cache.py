"""Small process-local LRU; immutable snapshots are keyed by their resolved ID."""
import json
from collections import OrderedDict
from threading import Lock


class ResponseCache:
    def __init__(self, max_bytes: int = 8 * 1024 * 1024, max_entries: int = 32):
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self.bytes = 0
        self.entries = OrderedDict()
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            value = self.entries.get(key)
            if value is None:
                return None
            self.entries.move_to_end(key)
        # Each caller gets its own value, never shared mutable model objects.
        return json.loads(value)

    def put(self, key, value):
        encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
        if len(encoded) > self.max_bytes:
            return
        with self.lock:
            previous = self.entries.pop(key, None)
            if previous is not None:
                self.bytes -= len(previous)
            self.entries[key] = encoded
            self.bytes += len(encoded)
            while self.bytes > self.max_bytes or len(self.entries) > self.max_entries:
                _, removed = self.entries.popitem(last=False)
                self.bytes -= len(removed)
