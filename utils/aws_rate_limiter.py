from pyrate_limiter import Duration, Rate, Limiter, BucketFullException, RedisBucket
from redis import Redis
import os
import glueops.setup_logging

logger = glueops.setup_logging.configure(level=os.environ.get('LOG_LEVEL', 'INFO'))




class RateLimiterUtil:
    def __init__(self, redis_url):
        self.redis_client = Redis.from_url(redis_url)

        # Initialize AWS ACM limiters
        self.aws_acm_describe_certificate_limiter = self.create_limiter("ratelimit:aws:acm:describecertificate", 10, Duration.SECOND)
        self.aws_acm_import_certificate_limiter = self.create_limiter("ratelimit:aws:acm:importcertificate", 1, Duration.SECOND)
        self.aws_acm_request_certificate_limiter = self.create_limiter("ratelimit:aws:acm:requestcertificate", 5, Duration.SECOND)
        self.aws_acm_delete_certificate_limiter = self.create_limiter("ratelimit:aws:acm:deletecertificate", 5, Duration.SECOND)

    def try_acquire(self, limiter, item_key):
        logger.info(f"Checking rate limit for: {item_key} ")
        limiter.try_acquire(item_key, raise_when_fail=True, max_delay=8000)
        return True

    def create_limiter(self, key, rate, duration):
        bucket = RedisBucket.init([Rate(rate, duration)], self.redis_client, key)
        return Limiter(bucket)

    def allow_request_aws_acm_describe_certificate(self):
        return self.try_acquire(self.aws_acm_describe_certificate_limiter, "aws_acm_describe_certificate")
        
    def allow_request_aws_acm_import_certificate(self):
        return self.try_acquire(self.aws_acm_import_certificate_limiter, "aws_acm_import_certificate")

    def allow_request_aws_acm_request_certificate(self):
        return self.try_acquire(self.aws_acm_request_certificate_limiter, "aws_acm_request_certificate")
        
    def allow_request_aws_acm_delete_certificate(self):
        return self.try_acquire(self.aws_acm_delete_certificate_limiter, "aws_acm_delete_certificate")
