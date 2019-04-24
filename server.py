import logging
import sys
from socket import socket, AF_INET, SOCK_DGRAM
from types import SimpleNamespace

from dns.dns_message import Query, Answer
from dns.dns_enums import RRType
from utils import resolver
from utils.zhuban_exceptions import ServerNotRespond

HOST = '127.0.0.1'
PORT = 53

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

handler = logging.StreamHandler(stream=sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logger.addHandler(handler)


def convert_query(query: Query):
    logger = logging.getLogger(f'{__name__}.{convert_query.__name__}')

    hostname = query.question.name
    inverse = hostname.endswith('.ip6.arpa') or hostname.endswith('.in-addr.arpa')
    ipv6 = query.question.type_ == RRType.AAAA if not inverse else hostname.endswith('.ip6.arpa')
    protocol = 'udp'
    server = None
    port = 53
    timeout = 1
    record_type = query.question.type_

    args = SimpleNamespace(
        inverse=inverse,
        ipv6=ipv6,
        hostname=hostname,
        protocol=protocol,
        server=server,
        port=port,
        timeout=timeout,
        record_type=record_type)

    logger.debug(f'Converted to args: {args}')

    return args


def process_request(query: Query) -> Answer:
    logger = logging.getLogger(f'{__name__}.{process_request.__name__}')

    args = convert_query(query)
    answer = resolver.resolve(args)
    answer.header.identifier = query.header.identifier

    return answer


def main():
    logger = logging.getLogger(f'{__name__}.{main.__name__}')

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((HOST, PORT))

    while True:
        message, address = sock.recvfrom(512)
        query = Query.from_bytes(message)
        logger.info(f'Got message from {address}')
        logger.info(f'domain: {query.question.name}, rr type: {query.question.type_}')

        try:
            answer = process_request(query)
            logger.info(f'Send answer to {address}')
            encoded_answer = answer.to_bytes()
            sock.sendto(encoded_answer, address)
        except ServerNotRespond as e:
            logger.exception(e.msg)


if __name__ == '__main__':
    main()
