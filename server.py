import logging
import sys
from collections import namedtuple
from socket import socket, AF_INET, SOCK_DGRAM

from dns.dns_message import Query, Answer
from dns.dns_enums import RRType
from utils import resolver
from utils.cache import cache
from utils.cache import load_cache, dump_cache
from utils.zhuban_exceptions import ServerNotRespond

HOST = '127.0.0.1'
PORT = 53

store = {}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

handler = logging.StreamHandler(stream=sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logger.addHandler(handler)

args_namespace = namedtuple('args_namespace', ['hostname', 'record_type', 'ipv6'])


def convert_query(query: Query):
    logger = logging.getLogger(f'{__name__}.{convert_query.__name__}')

    hostname = query.question.name
    inverse = hostname.endswith('.ip6.arpa') or hostname.endswith('.in-addr.arpa')
    ipv6 = query.question.type_ == RRType.AAAA if not inverse else hostname.endswith('.ip6.arpa')
    record_type = query.question.type_

    args = args_namespace(
        hostname=hostname,
        record_type=record_type,
        ipv6=ipv6)

    logger.debug(f'Converted to args: {args}')

    return args


@cache
def cache_resolve(args):
    return resolver.resolve(args)


def process_request(query: Query) -> Answer:
    logger = logging.getLogger(f'{__name__}.{process_request.__name__}')

    args = convert_query(query)

    if args.hostname.endswith('.beeline'):
        return Answer(query.header, [query.question], [], [], [])

    # answer = Answer.from_bytes(cache_resolve(args))
    answer = cache_resolve(args)
    answer.header.identifier = query.header.identifier

    return answer


def main():
    logger = logging.getLogger(f'{__name__}.{main.__name__}')

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((HOST, PORT))

    while True:
        try:
            message, address = sock.recvfrom(512)
            query = Query.from_bytes(message)
            logger.info(f'Got message from {address}')
            logger.info(f'domain: {query.question.name}, rr type: {query.question.type_}')

            answer = process_request(query)
            logger.info(f'Send answer to {address}')
            encoded_answer = answer.to_bytes()
            sock.sendto(encoded_answer, address)

            dump_cache()
        except ServerNotRespond as e:
            logger.exception(e.msg)
        except ConnectionResetError:
            pass


if __name__ == '__main__':
    load_cache()
    main()
