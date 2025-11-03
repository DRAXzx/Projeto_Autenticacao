import redis
import time

r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

def increment_key(key: str, expire: int) -> int:
    count = r.incr(key)
    if count == 1:
        r.expire(key, expire)
    return count

def is_blocked(key: str) -> bool:

    return r.exists(key) and int(r.ttl(key)) > 0

def set_temp_token(key: str, value: str, ttl: int = 600):

    r.setex(key, ttl, value)

def get_temp_token(key: str):

    value = r.get(key)
    if value:
        r.delete(key)
    return value
