import boto3
import redis
import json
import time
from redis import ConnectionPool, Redis

class RedisCache:
    def __init__(self, redis_url=''):
        self.client = Redis(connection_pool=ConnectionPool.from_url(redis_url))
        

    def get(self, key):
        """Retrieve data from the cache."""
        value = self.client.get(key)
        return json.loads(value) if value else None

    def set(self, key, value, ttl=60):
        """Save data to the cache with a TTL."""
        value_json = json.dumps(value)
        self.client.setex(key, ttl, value_json)