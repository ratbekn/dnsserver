import datetime
import functools
import logging
import sys
from collections import namedtuple

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s', datefmt='%S:%M:%H')

handler = logging.StreamHandler(stream=sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logger.addHandler(handler)

cache_store = {}

Record = namedtuple('Record', ['ttl', 'add_time', 'rr'])


day_seconds = 60 * 60 * 24


def cache(resolve):
    @functools.wraps(resolve)
    def wrapped(*args):
        logger.debug(f'Query with args: {args}')

        key = tuple(args)

        logger.debug(f'Key for query: {key}')

        if (key not in cache_store
                or (datetime.datetime.now() - cache_store[key].add_time).total_seconds() > cache_store[key].ttl):
            logger.debug(f'Either no record with key or record is outdated')
            answer = resolve(*args)

            ttl = min(answer_rr.ttl for answer_rr in answer.answers) if answer.answers else day_seconds
            logger.debug(f'ttl: {ttl}')

            cache_store[key] = Record(ttl, datetime.datetime.now(), answer)
        else:
            logger.debug('Record from cache')

        return cache_store[key].rr

    return wrapped
