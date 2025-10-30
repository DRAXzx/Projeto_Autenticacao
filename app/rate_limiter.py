import time
import threading

class LoginRateLimiter:
    def __init__(self, max_attempts=3, block_time=600):
        self.max_attempts = max_attempts
        self.block_time = block_time  
        self.attempts = {}
        self.lock = threading.Lock()

    def _is_blocked(self, key: str) -> bool:
        if key not in self.attempts:
            return False
        _, unblock_time = self.attempts[key]
        return time.time() < unblock_time

    def register_failure(self, key: str):
        with self.lock:
            attempts, unblock_time = self.attempts.get(key, [0, 0])
            now = time.time()

            if now >= unblock_time:
                attempts = 0
                unblock_time = 0

            attempts += 1

            if attempts >= self.max_attempts:
                unblock_time = now + self.block_time
                print(f"[RateLimiter] {key} bloqueado até {time.ctime(unblock_time)}")

            self.attempts[key] = [attempts, unblock_time]

    def reset(self, key: str):
        with self.lock:
            if key in self.attempts:
                del self.attempts[key]

    def check_allowed(self, key: str) -> bool:
        with self.lock:
            return not self._is_blocked(key)

    def get_time_remaining(self, key: str) -> int:
        with self.lock:
            if key not in self.attempts:
                return 0
            _, unblock_time = self.attempts[key]
            remaining = int(unblock_time - time.time())
            return max(0, remaining)
