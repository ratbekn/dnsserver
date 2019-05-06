import datetime
import functools
import itertools
import json
import logging
import sys
from collections import defaultdict
from collections import namedtuple

from dns.dns_message import Answer

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s', datefmt='%S:%M:%H')

handler = logging.StreamHandler(stream=sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logger.addHandler(handler)

cache_store = defaultdict(dict)

Record = namedtuple('Record', ['ttl', 'add_time', 'data'])

day_seconds = 60 * 60 * 24


def load_cache():
    global cache_store
    with open('cache.json') as cache_file:
        cache_store = json.load(cache_file, object_hook=lambda x: defaultdict(dict, x))


def dump_cache():
    with open('cache.json', 'w') as cache_file:
        json.dump(cache_store, cache_file, default=str)


def cache(resolve):
    @functools.wraps(resolve)
    def wrapped(*args):
        logger.debug(f'Query with args: {args}')

        rr_type = str(args[0].record_type.value)
        hostname = args[0].hostname

        logger.debug(f'Key for query: {rr_type}, {hostname}')

        if (hostname not in cache_store[rr_type]
                or ((datetime.datetime.now()
                    - datetime.datetime.strptime(
                            cache_store[rr_type][hostname][1], '%Y-%m-%d %H:%M:%S.%f')).total_seconds()
                    > cache_store[rr_type][hostname][0])):
            logger.debug(f'Either no record with key or record is outdated')
            answer = resolve(*args)

            all_rrs = sorted(
                itertools.chain(answer.answers, answer.authorities, answer.additions), key=lambda rr: rr.type_)

            for resource_type, resource_records in itertools.groupby(all_rrs, key=lambda record: record.type_):
                key_func = lambda record: record.name
                resources = cache_store[str(resource_type.value)]
                for domain, domain_records in itertools.groupby(sorted(resource_records, key=key_func), key=key_func):
                    domain_records = list(domain_records)

                    ttl = min(record.ttl for record in domain_records)

                    logger.debug(f'ttl: {ttl}')

                    resources[domain] = (
                        ttl, str(datetime.datetime.now()),
                        Answer(answer.header, answer.questions, domain_records, [], []))

            if not answer.answers:
                cache_store[rr_type][hostname] = (
                    60 * 60 * 24, str(datetime.datetime.now()),
                    Answer(answer.header, answer.questions, [], [], []))
        else:
            logger.debug('Record from cache')

        return cache_store[rr_type][hostname][2]

    return wrapped
