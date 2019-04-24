import io
import logging
import socket
import sys
import unittest
from argparse import Namespace

import pytest


from dns.dns_message import (
    Query, Answer, _Header, _Question, _ResourceRecord,
    _NSResourceData, _SOAResourceData, _AResourceData, _PTRResourceData)
from dns.dns_enums import (
    RRType, MessageType, ResponseType)
from unittest import mock
from utils import (
    resolver, get_user_log_level_selection
)
from utils.zhuban_exceptions import InvalidServerResponse


@pytest.fixture()
def args():
    return {
        'hostname': 'yandex.ru',
        'record_type': RRType.A,
        'protocol': 'udp',
        'server': '8.8.8.8',
        'port': 53,
        'timeout': 10
    }


def test_get_user_log_level_selection(monkeypatch):
    handle = io.StringIO('y')
    monkeypatch.setattr(sys, 'stdin', handle)

    assert get_user_log_level_selection('') == logging.DEBUG


def test_get_root_servers():
    assert resolver.get_root_servers() == {
        '198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
        '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
        '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
        '202.12.27.33',
    }


def test_get_ip_reverse_notation():
    assert (resolver.get_ip_reverse_notation('77.88.55.55')
            == '55.55.88.77.in-addr.arpa')


@mock.patch('utils.resolver.udp_query')
def test_empty_server_response(mock_udp_query, args):
    mock_udp_query.return_value = b''

    with pytest.raises(InvalidServerResponse):
        resolver.get_answer(**args)


@mock.patch('utils.resolver.udp_query')
def test_invalid_server_response_1(mock_udp_query, args):
    mock_udp_query.return_value = \
        b'\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    with pytest.raises(InvalidServerResponse):
        resolver.get_answer(**args)


@mock.patch('utils.resolver.udp_query')
def test_record_a(mock_udp_query, args):
    mock_udp_query.return_value = \
        b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06yandex' \
        b'\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00' \
        b'\x00\x00\x00\x04\xd5\xb4\xcc\x3e'

    answer = resolver.get_answer(**args)

    assert answer.answers[0].name == 'yandex.com'
    assert answer.answers[0].data.ip == '213.180.204.62'


@mock.patch('utils.resolver.get_root_servers')
@mock.patch('utils.resolver.get_answer')
def test_find_name_servers(mock_get_answer, mock_get_root_servers):
    mock_get_root_servers.return_value = {'198.41.0.4'}

    header = _Header(
        9633, MessageType.RESPONSE, question_count=1, answer_count=4)
    questions = [_Question('vk.com', type_=RRType.NS)]
    answers = [_ResourceRecord(
        'vk.com', type_=RRType.NS, length=18,
        data=_NSResourceData(
            b'\xc0\x0c\x00\x02\x00\x01\x00\x00\x02\x0b\x00\x12'
            b'\x03ns4\x09vkontakte\x02ru\x00', offset=0))]
    mock_get_answer.return_value = Answer(header, questions, answers, [], [])

    assert resolver.find_name_servers(
        'vk.com', protocol='udp', port=53, timeout=10) == ['ns4.vkontakte.ru']


@mock.patch('utils.resolver.get_answer')
@mock.patch('utils.resolver.find_name_servers')
def test_get_primary_name_server_1(mock_find_name_servers, mock_get_answer):
    mock_find_name_servers.return_value = ['ns4.vkontakte.ru',
                                           'ns2.vkontakte.ru']

    header = _Header(
        9633, MessageType.RESPONSE, question_count=1, answer_count=4)
    questions = [_Question('vk.com', type_=RRType.NS)]
    answers = [_ResourceRecord(
        'vk.com', type_=RRType.NS, length=18,
        data=_SOAResourceData(
            b'\xc0\x0c\x00\x06\x00\x01\x00\x00\x02\x0b\x00\x44'
            b'\x03ns1\x09vkontakte\x02ru\x00'
            b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', offset=0))]
    mock_get_answer.return_value = Answer(header, questions, answers, [], [])

    assert resolver.get_primary_name_server(
        'vk.com', protocol='udp', port=53, timeout=10) == 'ns1.vkontakte.ru'


@mock.patch('utils.resolver.get_answer')
@mock.patch('utils.resolver.find_name_servers')
def test_get_primary_name_server_2(mock_find_name_servers, mock_get_answer):
    mock_find_name_servers.return_value = ['ns4.vkontakte.ru',
                                           'ns2.vkontakte.ru']

    header = _Header(
        9633, MessageType.RESPONSE, question_count=1, answer_count=0)
    questions = [_Question('vk.com', type_=RRType.NS)]
    mock_get_answer.return_value = Answer(header, questions, [], [], [])

    assert resolver.get_primary_name_server(
        'vk.com', protocol='udp', port=53, timeout=10) is None


@mock.patch('utils.resolver.get_answer')
def test_resolve_ip4_recursive(mock_get_answer):
    args = Namespace(hostname='vk.com', protocol='udp', server='8.8.8.8',
                     port=53, timeout=10, inverse=False, dump=False,
                     debug=False, ipv6=False)

    header = _Header(
        1823, MessageType.RESPONSE, question_count=1, answer_count=1)
    questions = [_Question('vk.com')]
    answers = [_ResourceRecord(
        'vk.com', type_=RRType.A, length=4,
        data=_AResourceData(b'\x57\xf0\xb6\xe0'))]
    mock_get_answer.return_value = Answer(header, questions, answers, [], [])

    assert resolver.resolve(args).answers[0].data.ip == '87.240.182.224'


@mock.patch('utils.resolver.get_answer')
def test_resolve_reverse_lookup(mock_get_answer):
    args = Namespace(hostname='87.240.182.224', protocol='udp',
                     server='8.8.8.8', port=53, timeout=10, inverse=True,
                     dump=False, debug=False, ipv6=False)

    f_header = _Header(
        1823, MessageType.RESPONSE, question_count=1, answer_count=0,
        authority_count=1)
    s_header = _Header(
        2938, MessageType.RESPONSE, question_count=1, answer_count=1)
    questions = [_Question('vk.com')]
    authorities = [_ResourceRecord(
        'vk.com', type_=RRType.NS, length=18,
        data=_NSResourceData(
            b'\xc0\x0c\x00\x02\x00\x01\x00\x00\x02\x0b\x00\x12'
            b'\x03ns4\x09vkontakte\x02ru\x00', offset=0))]
    answers = [_ResourceRecord(
        'vk.com', type_=RRType.PTR, length=8,
        data=_PTRResourceData(b'\x02vk\x03com\x00'))]
    first = Answer(f_header, questions, [], authorities, [])
    second = Answer(s_header, questions, answers, [], [])
    mock_get_answer.side_effect = [first, second]

    assert (resolver.resolve_reverse_lookup(args).answers[0]
            .data.name == 'vk.com')


@mock.patch('utils.resolver.get_answer')
@mock.patch('utils.resolver.find_name_servers')
def test_get_zone_dump(mock_find_name_servers, mock_get_answer):
    mock_find_name_servers.return_value = ['ns1.vk.ru', 'ns4.vk.ru']

    f_header = _Header(2932, MessageType.RESPONSE, 1,
                       response_type=ResponseType.REFUSED)
    s_header = _Header(2928, MessageType.RESPONSE, 1, answer_count=1)
    questions = [_Question('vk.com', RRType.AXFR)]
    mock_get_answer.side_effect = [Answer(f_header, questions, [], [], []),
                                   Answer(s_header, questions, [], [], [])]

    assert not resolver.get_zone_dump('vk.com', port=53, timeout=10).answers


class TestSendMessage(unittest.TestCase):
    def setUp(self):
        self.argv = {
            'hostname': 'yandex.com',
            'record_type': RRType.A,
            'server': '8.8.8.8',
            'port': 53,
            'protocol': 'udp',
            'timeout': 10
        }

    @mock.patch('utils.resolver.udp_query')
    def test_too_long_message(self, mock_udp_query):
        mock_udp_query.return_value = bytearray(513)

        self.assertRaises(InvalidServerResponse, resolver.send_query,
                          **self.argv)

    @mock.patch('utils.resolver.udp_query', side_effect=socket.timeout)
    def test_timeout(self, mock_udp_query):
        self.assertRaises(socket.timeout, resolver.send_query, **self.argv)

    @mock.patch('utils.resolver.udp_query', side_effect=socket.gaierror)
    def test_gaierror(self, mock_udp_query):
        self.assertRaises(socket.gaierror, resolver.send_query, **self.argv)

    @mock.patch('socket.socket.recv', side_effect=ConnectionError)
    def test_connectionerror(self, mock_connectionerror):
        self.assertRaises(
            ConnectionError, resolver.send_query, **self.argv
        )


class TestUDPQuery(unittest.TestCase):
    def setUp(self):
        self.argv = {
            'server': '8.8.8.8',
            'port': 53,
            'timeout': 10
        }
        self.bytes_ = Query('yandex.com').to_bytes()

    @mock.patch(
        'socket.socket.recv',
        return_value=b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                     b'\x06yandex\x03com\x00\x00\x01\x00\x01'
                     b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00'
                     b'\x04\xd5\xb4\xcc\x3e')
    def test_A(self, mock_socket_recv):
        response = resolver.udp_query(self.bytes_, **self.argv)
        answer = Answer.from_bytes(response)

        self.assertEqual(answer.answers[0].name, 'yandex.com')
        self.assertEqual(answer.answers[0].data.ip, '213.180.204.62')

    @mock.patch('socket.socket.recv', side_effect=socket.timeout)
    def test_timeout(self, mock_socket_recv):
        self.assertRaises(
            socket.timeout, resolver.udp_query, self.bytes_, **self.argv
        )

    @mock.patch('socket.socket.recv', side_effect=socket.gaierror)
    def test_gaierror(self, mock_socket_recv):
        self.assertRaises(
            socket.gaierror, resolver.udp_query, self.bytes_, **self.argv
        )

    @mock.patch('socket.socket.recv', side_effect=ConnectionError)
    def test_connectionerror(self, mock_connectionerror):
        self.assertRaises(
            ConnectionError, resolver.udp_query, self.bytes_, **self.argv
        )


class TestTCPQuery(unittest.TestCase):
    def setUp(self):
        self.argv = {
            'server': '8.8.8.8',
            'port': 53,
            'timeout': 10
        }
        self.bytes_ = Query('google.com').to_bytes()

    def mock_recv(bufsize):
        size = b'\x00\x2c'
        response = \
            b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' \
            b'\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c' \
            b'\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x4a\x7d\xe8\xe7'
        if bufsize == 2:
            return size
        else:
            return response

    @mock.patch('socket.socket.recv', side_effect=mock_recv)
    def test_A(self, mock_socket_recv):
        response = resolver.tcp_query(self.bytes_, **self.argv)
        answer = Answer.from_bytes(response)

        self.assertEqual(answer.questions[0].name, 'google.com')
        self.assertEqual(answer.answers[0].data.ip, '74.125.232.231')

    @mock.patch('socket.socket.recv', side_effect=socket.timeout)
    def test_timeout(self, mock_socket_recv):
        self.assertRaises(
            socket.timeout, resolver.tcp_query, self.bytes_, **self.argv
        )

    @mock.patch('socket.socket.recv', side_effect=socket.gaierror)
    def test_gaierror(self, mock_socket_recv):
        self.assertRaises(
            socket.gaierror, resolver.tcp_query, self.bytes_, **self.argv
        )

    @mock.patch('socket.socket.recv', side_effect=ConnectionError)
    def test_connectionerror(self, mock_connectionerror):
        self.assertRaises(
            ConnectionError, resolver.tcp_query, self.bytes_, **self.argv
        )
