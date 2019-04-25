import ipaddress
import logging
import random
import socket
import struct
import sys

from dns import dns_servers
from dns.dns_enums import RRType, ResponseType
from dns.dns_message import Query, Answer
from .zhuban_exceptions import (
    InvalidAnswer, InvalidServerResponse, ErrorResponse, ServerNotRespond
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

formatter = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s', datefmt='%S:%M:%H')

handler = logging.StreamHandler(stream=sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logger.addHandler(handler)


def get_root_servers():
    return dns_servers.root_servers


def find_name_servers(hostname,
                      *, protocol, port, timeout) -> list:
    """
    Находит все name server'ы для домена
    :param hostname: домен
    :param protocol: протокол сетевого уровня
    :param port: порт
    :param timeout: время ожидания ответа от сервера
    :return: список ip адресов name server'ов
    """
    logger = logging.getLogger(f'{__name__}.{find_name_servers.__name__}')

    logger.debug('--- Finding name servers ---')

    server = random.choice(list(get_root_servers()))
    while True:
        answer = get_answer(hostname, RRType.NS,
                            protocol=protocol, server=server,
                            port=port, timeout=timeout)

        if answer.header.response_type != ResponseType.NO_ERROR:
            raise ErrorResponse(data=answer)

        logger.debug(f'Got answer: {answer}')

        if any(ans for ans in answer.authorities if ans.type_ == RRType.SOA):
            break

        if answer.header.answer_count:
            break

        if (not answer.header.answer_count
                and any(ns for ns in answer.authorities
                        if ns.type_ == RRType.NS)):
            server = random.choice(answer.authorities).data.name

    logger.debug('=== Finding name servers ===')

    return ([ans for ans in answer.answers if ans.type_ == RRType.NS]
            + [ans for ans in answer.authorities if ans.type_ == RRType.SOA])


def get_primary_name_server(hostname,
                            *, protocol, port, timeout):
    """
    Отдаёт ip адрес primary (master) сервера для домена
    :param hostname: домен
    :param protocol: протокол сетевого уровня
    :param port: порт
    :param timeout: время ожидания ответа от сервера
    :return: ip адрес primary сервера
    """
    logger = logging.getLogger(f'{__name__}.{get_primary_name_server.__name__}')

    logger.debug('--- Getting primary name server ---')

    try:
        name_servers = find_name_servers(hostname,
                                         protocol=protocol, port=port,
                                         timeout=timeout)
    except ErrorResponse as e:
        raise e

    found_name_servers = '\n'.join([ns.data.name for ns in name_servers if ns.type_ == RRType.NS]
                                   + [ns.data.name_server for ns in name_servers if ns.type_ == RRType.SOA])
    logger.debug(f'Finded name servers: {found_name_servers}')

    for name_server in name_servers:
        if name_server.type_ == RRType.SOA:
            return name_server.data.name_server

    for name_server_rr in name_servers:
        name_server = (
            name_server_rr.data.name_server if name_server_rr.type_ == RRType.SOA else name_server_rr.data.name)

        try:
            answer = get_answer(hostname, RRType.SOA,
                                protocol=protocol,
                                server=name_server, port=port, timeout=timeout)
        except socket.timeout:
            continue
        except socket.gaierror:
            continue

        if answer.header.answer_count:
            for answer in answer.answers:
                if answer.type_ == RRType.SOA:
                    logger.debug('=== Getting primary name server ===')

                    return answer.data.name_server

    logger.error("Primary name server didn't find")
    logger.error("Our last hope")

    return '8.8.8.8'


def tcp_query(query: bytes, *, server, port, timeout) -> bytes:
    """
    Отправляет dns-запрос представленный в виде байт через TCP протокол

    :param server: адрес сервера
    :param port: порт
    :param timeout: время ожидания ответа от сервера
    :param bytes query: объект bytes, содержащий запрос
    :raise socket.timeout: превышено время ожидания
    :raise socket.gaierror: ошибки связанные с адресом
    :return: объект bytes содержащий ответ от сервера
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, port))

        qsize = struct.pack('!H', len(query))

        try:
            s.sendall(qsize + query)

            receive_size = struct.unpack('!H', s.recv(2))[0]

            response = s.recv(receive_size)
        except socket.timeout:
            raise
        except socket.gaierror:
            raise
        except ConnectionError:
            raise

    return response


def udp_query(query: bytes, *, server, port, timeout) -> bytes:
    """
    Отправляет dns-запрос представленный в виде байт через UDP протокол

    :param bytes query: объект bytes, содержащий запрос
    :param server: адрес сервера
    :param port: порт
    :param timeout: время ожидания ответа от сервера
    :raise socket.timeout: превышено время ожидания
    :raise socket.gaierror: ошибки связанные с адресом
    :return: объект bytes содержащий ответ от сервера
    """
    logger = logging.getLogger(f'{__name__}.{udp_query.__name__}')

    logger.debug('--- Start udp query ---')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)

        # logger.debug(f'Send query:\n {str(Query.from_bytes(query)).strip()}')
        logger.debug(f'Send query to server {(server, port)}')

        try:
            s.sendto(query, (server, port))
            response = s.recv(1024)
        except socket.timeout:
            raise ServerNotRespond(f'Сервер {server}:{port} не отвечает')
        except socket.gaierror:
            raise

    logger.debug('=== End udp query ===')
    return response


def send_query(*, hostname, record_type: RRType,
               protocol: str, server: ipaddress, port, timeout) -> bytes:
    """
    Формирует пакет запроса, отправляет его и возвращает ответ от сервера

    :param hostname: доменное имя
    :param record_type: тип требуемой DNS-записи (A, NS, PTR, и.т.д)
    :param protocol: протокол сетевего уровня
    :param server: адрес DNS-сервера
    :param port: порт DNS-сервера
    :param timeout: время ожидания ответа от сервера
    :return: объект Answer представляющий ответ от сервера
    """

    query = Query(hostname, rr_type=record_type)
    query = query.to_bytes()

    try:
        args = {'server': server, 'port': port, 'timeout': timeout}
        response = (udp_query(query, **args) if protocol.lower() == 'udp'
                    else tcp_query(query, **args))
    except socket.timeout:
        raise
    except socket.gaierror:
        raise
    except ConnectionError:
        raise

    if protocol == 'udp' and len(response) > 512:
        raise InvalidServerResponse

    return response


def get_ip_reverse_notation(ip, *, ipv6=False):
    """
    Возвращает обратную нотацию ip (используется для определения имени узла
    по его IP)

    :param ip: доменное имя
    :param ipv6: флаг для IPv6
    :return:
    """

    divider = ':' if ipv6 else '.'
    suffix = '.ip6.arpa' if ipv6 else '.in-addr.arpa'

    hostname = ((t for t in reversed(ip.exploded) if not t == divider) if ipv6
                else reversed(ip.split(divider)))

    return '.'.join(hostname) + suffix


def get_zone_dump(hostname, *, port, timeout):
    """
    Возвращает все поддомены в домене используя axfr запрос к Name Server'у
    домена
    :param hostname: домен
    :param port: порт
    :param timeout: время ожидания ответа от сервера
    :return: ответ от сервера со всеми поддоменами домена
    """

    name_servers = find_name_servers(hostname,
                                     protocol='udp', port=port,
                                     timeout=timeout)

    answer = None
    for ns in name_servers:
        answer = get_answer(hostname, RRType.AXFR, protocol='tcp',
                            server=ns, port=port, timeout=timeout)

        if answer.header.answer_count:
            break

    return answer


def get_answer(hostname, record_type,
               *, inverse=False, ipv6=False, protocol, server, port, timeout):
    # if inverse:
    #     hostname = get_ip_reverse_notation(hostname, ipv6=ipv6)

    try:
        response = send_query(hostname=hostname, record_type=record_type,
                              protocol=protocol, server=server,
                              port=port, timeout=timeout)

        answer = Answer.from_bytes(response)
    except socket.timeout:
        raise
    except socket.gaierror:
        raise
    except InvalidAnswer as e:
        raise InvalidServerResponse from e

    return answer


def resolve(args):
    logger = logging.getLogger(f'{__name__}.{resolve.__name__}')

    logger.debug('--- Resolving start ---')

    if args.hostname.endswith('.ip6.arpa') or args.hostname.endswith('.in-addr.arpa'):
        return resolve_reverse_lookup(args)

    hostname = args.hostname
    protocol = 'udp'
    server = None
    port = 53
    timeout = 5
    record_type = args.record_type

    if server is None:
        logger.debug('--- Finding primary server ---')
        try:
            server = get_primary_name_server(
                hostname, protocol=protocol, port=port, timeout=timeout)
        except ErrorResponse as e:
            return e.data
        except ServerNotRespond as e:
            raise e

        logger.debug('=== Finding primary server ===')
        logger.debug(f'Server: {server}')

    try:
        logger.debug('--- Getting answer ---')
        answer = get_answer(hostname, record_type, inverse=False,
                            ipv6=args.ipv6, protocol=protocol, server=server,
                            port=port, timeout=timeout)
    except socket.timeout:
        raise ServerNotRespond(f'Авторитетный для {hostname} сервер {server} не отвечает')
    except socket.gaierror:
        logger.exception('')

    logger.debug('=== Getting answer ===')

    logger.debug('=== Resolving end ===')
    return answer


def resolve_reverse_lookup(args):
    hostname = args.hostname
    protocol = 'udp'
    server = None
    port = 53
    timeout = 5

    if server is None:
        servers = (dns_servers.revers_lookup_servers_ip6 if args.ipv6
                   else dns_servers.revers_lookup_servers)
        server = random.choice(list(servers))

    answer = get_answer(hostname, RRType.PTR, inverse=True,
                        ipv6=args.ipv6, protocol=protocol, server=server,
                        port=port, timeout=timeout)

    while (not answer.header.answer_count
           and any(ns for ns in answer.authorities
                   if ns.type_ == RRType.NS)):
        server = random.choice(answer.authorities).data.name
        answer = get_answer(hostname, RRType.PTR, inverse=True,
                            ipv6=args.ipv6, protocol=protocol,
                            server=server,
                            port=port, timeout=timeout)

    return answer
