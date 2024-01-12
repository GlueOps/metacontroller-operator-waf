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
        return self.client.get(key)

    def set(self, key, value, ttl=1):
        """Save data to the cache with a TTL."""
        self.client.setex(key, ttl, value)