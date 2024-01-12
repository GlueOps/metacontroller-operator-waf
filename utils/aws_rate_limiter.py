from pyrate_limiter import Duration, Rate, Limiter, BucketFullException, RedisBucket
from redis import ConnectionPool, Redis
import sys
import glueops.setup_logging
import traceback
import os

logger = glueops.setup_logging.configure(level=os.environ.get('LOG_LEVEL', 'INFO'))




class RateLimiterUtil:
    def __init__(self, redis_url):
        self.redis_client = Redis(connection_pool=ConnectionPool.from_url(redis_url))

        # Initialize AWS ACM limiters
        self.aws_acm_describe_certificate_limiter = self.create_limiter("ratelimit:aws:acm:describecertificate", 10, Duration.SECOND)
        self.aws_acm_import_certificate_limiter = self.create_limiter("ratelimit:aws:acm:importcertificate", 1, Duration.SECOND)
        self.aws_acm_request_certificate_limiter = self.create_limiter("ratelimit:aws:acm:requestcertificate", 5, Duration.SECOND)
        self.aws_acm_delete_certificate_limiter = self.create_limiter("ratelimit:aws:acm:deletecertificate", 5, Duration.SECOND)

    def check(self, limiter, item_key):
        try:
            logger.info(f"Checking rate limit for: {item_key} ")
            limiter.delay_or_raise(item=item_key)
            return True
        except BucketFullException as err:
            logger.error(err)
            logger.error(err.meta_info)
            raise
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.critical("Some unknown exception occured. Going to exit(1) now.")
            os._exit(1)

    def create_limiter(self, key, rate, duration):
        bucket = RedisBucket.init([Rate(rate, duration)], self.redis_client, key)
        return Limiter(bucket, raise_when_fail=True, max_delay=120000) # 30s

    def allow_request_aws_acm_describe_certificate(self):
        return self.check(self.aws_acm_describe_certificate_limiter, "aws_acm_describe_certificate")
        
    def allow_request_aws_acm_import_certificate(self):
        return self.check(self.aws_acm_import_certificate_limiter, "aws_acm_import_certificate")

    def allow_request_aws_acm_request_certificate(self):
        return self.check(self.aws_acm_request_certificate_limiter, "aws_acm_request_certificate")
        
    def allow_request_aws_acm_delete_certificate(self):
        return self.check(self.aws_acm_delete_certificate_limiter, "aws_acm_delete_certificate")
