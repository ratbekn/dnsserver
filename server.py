from socket import socket, AF_INET, SOCK_DGRAM, timeout
from types import SimpleNamespace

from dns.dns_message import Query, Answer
from dns.dns_enums import RRType
from utils import resolver
from utils.zhuban_exceptions import ServerNotRespond


HOST = '127.0.0.1'
PORT = 53


def convert_query(query: Query):
    # что если запрос на обратный ipv6?
    hostname = query.question.name
    inverse = hostname.endswith('.ip6.arpa') or hostname.endswith('.in-addr.arpa')
    ipv6 = query.question.type_ == RRType.AAAA if not inverse else hostname.endswith('.ip6.arpa')
    protocol = 'udp'
    server = None
    port = 53
    timeout = 10
    record_type = query.question.type_

    return SimpleNamespace(
        inverse=inverse,
        ipv6=ipv6,
        hostname=hostname,
        protocol=protocol,
        server=server,
        port=port,
        timeout=timeout,
        record_type=record_type)


def process_request(query: Query) -> Answer:
    args = convert_query(query)
    answer = resolver.resolve(args)
    answer.header.identifier = query.header.identifier

    return answer


def main():
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((HOST, PORT))

    while True:
        message, address = sock.recvfrom(512)
        query = Query.from_bytes(message)
        print(f'Got message \n{query} \nfrom {address}')

        try:
            answer = process_request(query)
            print(f'Send answer \n{answer} \nto {address}')
            encoded_answer = answer.to_bytes()
            sock.sendto(encoded_answer, address)
        except ServerNotRespond as e:
            print(e.msg)


if __name__ == '__main__':
    main()
