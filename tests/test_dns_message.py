import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from dns.dns_message import (
    _encode_number, _decode_number, _encode_name, _decode_name, _Header,
    _Question, _ResourceRecord, Query, Answer, _AResourceData
)
from dns.dns_enums import (
    MessageType, QueryType, ResponseType, RRType,
    RRClass
)


class TestEncodeNumber(unittest.TestCase):
    def test_negative(self):
        number = -1

        self.assertRaises(ValueError, _encode_number, number)

    def test_zero(self):
        number = 0

        expected = b'\x00\x00'
        actual = _encode_number(number)

        self.assertEqual(expected, actual)

    def test_positive(self):
        number = 27

        expected = b'\x00\x1b'
        actual = _encode_number(number)

        self.assertEqual(expected, actual)

    def test_positive_1(self):
        number = 16

        expected = b'\x00\x10'
        actual = _encode_number(number)

        self.assertEqual(expected, actual)


class TestDecodeNumber(unittest.TestCase):
    def test_zero(self):
        in_bytes = b'\x00\x00'

        expected = 0
        actual = _decode_number(in_bytes)

        self.assertEqual(expected, actual)

    def test_positive(self):
        in_bytes = b'\x00\x1b'

        expected = 27
        actual = _decode_number(in_bytes)

        self.assertEqual(expected, actual)

    def test_positive_1(self):
        in_bytes = b'\x00\x10'

        expected = 16
        actual = _decode_number(in_bytes)

        self.assertEqual(expected, actual)


class TestEncodeString(unittest.TestCase):
    def test_one(self):
        domain_name = 'www.yandex.ru'

        expected = b'\x03www\x06yandex\x02ru\x00'
        actual = _encode_name(domain_name)

        self.assertEqual(expected, actual)

    def test_two(self):
        domain_name = 'google.com'

        expected = b'\x06google\x03com\x00'
        actual = _encode_name(domain_name)

        self.assertEqual(expected, actual)


class TestDecodeString(unittest.TestCase):
    def test_labels(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x03www\x06yandex\x02ru\x00\x00\x01\x00\x01'

        expected = 'www.yandex.ru'
        offset = _Header.from_bytes(in_bytes, 0).offset
        actual = _decode_name(in_bytes, offset).decoded_

        self.assertEqual(expected, actual)

    def test_pointer(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x03www\x06yandex\x02ru\x00\x00\x01\x00\x01\xc0\x0c'
        expected = 'www.yandex.ru'
        actual = _decode_name(in_bytes, 31).decoded_

        self.assertEqual(expected, actual)


class TestHeaderInit(unittest.TestCase):
    def test_standard_query(self):
        header = _Header(1337, MessageType.QUERY, 1)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_query_with_several_questions(self):
        header = _Header(1337, MessageType.QUERY, 5)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 5)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_recursion_desired_query(self):
        header = _Header(1337, MessageType.QUERY, 1, is_recursion_desired=True)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, True)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_inverse_query(self):
        header = _Header(
            1337, MessageType.QUERY, 1, query_type=QueryType.INVERSE)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.INVERSE)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_status_query(self):
        header = _Header(
            1337, MessageType.QUERY, 1, query_type=QueryType.STATUS)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STATUS)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_complex_query(self):
        header = _Header(
            1337, MessageType.QUERY, 3, query_type=QueryType.INVERSE,
            is_recursion_desired=True)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 3)

        self.assertEqual(header.query_type, QueryType.INVERSE)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, True)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)


class TestHeaderEncodeFlags(unittest.TestCase):
    def test_standard_query(self):
        header = _Header(1337, MessageType.QUERY, 0)

        expected = b'\x00\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_recursive_standard_query(self):
        header = _Header(1337, MessageType.QUERY, 0, is_recursion_desired=True)

        expected = b'\x01\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_inverse_query(self):
        header = _Header(
            1337, MessageType.QUERY, 0, query_type=QueryType.INVERSE)

        expected = b'\x08\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_recursive_inverse_query(self):
        header = _Header(
            1337, MessageType.QUERY, 0, query_type=QueryType.INVERSE,
            is_recursion_desired=True)

        expected = b'\t\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_simple_answer(self):
        header = _Header(1337, MessageType.RESPONSE, 0)

        expected = b'\x80\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)


class TestHeaderToBytes(unittest.TestCase):
    def test_standard_query(self):
        header = _Header(256, MessageType.QUERY, 1)

        expected = b'\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)

    def test_query_with_two_questions(self):
        header = _Header(256, MessageType.QUERY, 2)

        expected = b'\x01\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)

    def test_query_with_several_questions(self):
        header = _Header(256, MessageType.QUERY, 5)

        expected = b'\x01\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)


class TestHeaderFromBytes(unittest.TestCase):
    def equal_headers(self, expected, actual):
        self.assertEqual(expected.identifier, actual.identifier)

        self.assertEqual(expected.message_type, actual.message_type)
        self.assertEqual(expected.query_type, actual.query_type)
        self.assertEqual(
            expected.is_authority_answer, actual.is_authority_answer)

        self.assertEqual(expected.is_truncated, actual.is_truncated)
        self.assertEqual(
            expected.is_recursion_desired, actual.is_recursion_desired)

        self.assertEqual(
            expected.is_recursion_available, actual.is_recursion_available)

        self.assertEqual(expected.response_type, actual.response_type)

        self.assertEqual(expected.question_count, actual.question_count)
        self.assertEqual(expected.answer_count, actual.answer_count)
        self.assertEqual(expected.authority_count, actual.authority_count)
        self.assertEqual(expected.additional_count, actual.additional_count)

    def test_no_error_answer(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'

        expected = _Header(256, MessageType.RESPONSE, 1, answer_count=1)
        actual = _Header.from_bytes(in_bytes, 0).header

        self.equal_headers(expected, actual)

    def test_no_error_rd_answer(self):
        in_bytes = b'\x01\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

        expected = _Header(256, MessageType.RESPONSE, 1, answer_count=1,
                           is_recursion_desired=True,
                           is_recursion_available=True)
        actual = _Header.from_bytes(in_bytes, 0).header

        self.equal_headers(expected, actual)


class TestQuestionInit(unittest.TestCase):
    def test_A_question(self):
        question = _Question('yandex.com')

        self.assertEqual(question.name, 'yandex.com')
        self.assertEqual(question.type_, RRType.A)
        self.assertEqual(question.class_, RRClass.IN)

    def test_NS_question(self):
        question = _Question('google.com', RRType.NS)

        self.assertEqual(question.name, 'google.com')
        self.assertEqual(question.type_, RRType.NS)
        self.assertEqual(question.class_, RRClass.IN)


class TestQuestionToBytes(unittest.TestCase):
    def test_A_question(self):
        question = _Question('docs.python.org')

        expected = b'\x04docs\x06python\x03org\x00\x00\x01\x00\x01'
        actual = question.to_bytes()

        self.assertEqual(expected, actual)

    def test_A_question_2(self):
        question = _Question('python.org')

        expected = b'\x06python\x03org\x00\x00\x01\x00\x01'
        actual = question.to_bytes()

        self.assertEqual(expected, actual)

    def test_NS_question(self):
        question = _Question('docs.python.org', type_=RRType.NS)

        expected = b'\x04docs\x06python\x03org\x00\x00\x02\x00\x01'
        actual = question.to_bytes()

        self.assertEqual(expected, actual)

    def test_NS_question_2(self):
        question = _Question('python.org', type_=RRType.NS)

        expected = b'\x06python\x03org\x00\x00\x02\x00\x01'
        actual = question.to_bytes()

        self.assertEqual(expected, actual)


class TestQuestionFromBytes(unittest.TestCase):
    def equal_questions(self, expected, actual):
        self.assertEqual(expected.name, actual.name)
        self.assertEqual(expected.type_, actual.type_)
        self.assertEqual(expected.class_, actual.class_)

    def test_A_question(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x04docs\x06python\x03org\x00\x00\x01\x00\x01'

        expected = _Question('docs.python.org', RRType.A)
        actual = _Question.from_bytes(in_bytes, 12).question

        self.equal_questions(expected, actual)

    def test_NS_question(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x06python\x03org\x00\x00\x02\x00\x01'

        expected = _Question('python.org', RRType.NS)
        actual = _Question.from_bytes(in_bytes, 12).question

        self.equal_questions(expected, actual)


class TestResourceRecordInit(unittest.TestCase):
    def test_A_rr(self):
        actual = _ResourceRecord(
            'google.com', type_=RRType.A, length=4,
            data='172.217.17.110')

        self.assertEqual(actual.name, 'google.com')
        self.assertEqual(actual.type_, RRType.A)
        self.assertEqual(actual.class_, RRClass.IN)
        self.assertEqual(actual.ttl, 0)
        self.assertEqual(actual.length, 4)
        self.assertEqual(actual.data, '172.217.17.110')


class TestDecodeRRData(unittest.TestCase):
    def test_A_type(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x06google\x03com\x00\x00\x01\x00\x01' \
                   b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04' \
                   b'\xac\xd9\x0en'

        actual = _ResourceRecord._decode_data(
            in_bytes, RRType.A, 4, 40)

        self.assertEqual('172.217.14.110', actual.ip)


class TestResourceRecordFromBytes(unittest.TestCase):
    def test_A_RR(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x06google\x03com\x00\x00\x01\x00\x01' \
                   b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04' \
                   b'\xac\xd9\x0en'

        actual = _ResourceRecord.from_bytes(in_bytes, 28).resource_record

        self.assertEqual('google.com', actual.name)
        self.assertEqual(RRType.A, actual.type_)
        self.assertEqual(RRClass.IN, actual.class_)
        self.assertEqual(0, actual.ttl)
        self.assertEqual(4, actual.length)
        self.assertEqual('172.217.14.110', actual.data.ip)

    def test_AAAA_RR(self):
        in_bytes = (b'\x2b\x74\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00'
                    b'\x06google\x03com\x00\x00\x1c\x00\x01'
                    b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10'
                    b'\x2a\x00\x14\x50\x40\x11\x08\x08\x00\x00\x00\x00'
                    b'\x00\x00\x10\x02')
        actual = _ResourceRecord.from_bytes(in_bytes, 28).resource_record

        self.assertEqual('google.com', actual.name)
        self.assertEqual(RRType.AAAA, actual.type_)
        self.assertEqual(RRClass.IN, actual.class_)
        self.assertEqual(300, actual.ttl)
        self.assertEqual(16, actual.length)
        self.assertEqual('2a00:1450:4011:0808:0000:0000:0000:1002',
                         actual.data.ip)


class TestQueryInit(unittest.TestCase):
    def test_standard_A_query(self):
        actual = Query('google.com', RRType.A)

        self.assertEqual(actual.header.message_type, MessageType.QUERY)
        self.assertEqual(actual.header.question_count, 1)

        self.assertEqual(actual.header.query_type, QueryType.STANDARD)
        self.assertEqual(actual.header.is_authority_answer, False)
        self.assertEqual(actual.header.is_truncated, False)
        self.assertEqual(actual.header.is_recursion_desired, True)
        self.assertEqual(actual.header.is_recursion_available, False)
        self.assertEqual(actual.header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(actual.header.answer_count, 0)
        self.assertEqual(actual.header.authority_count, 0)
        self.assertEqual(actual.header.additional_count, 0)

        self.assertEqual(actual.question.name, 'google.com')
        self.assertEqual(actual.question.type_, RRType.A)
        self.assertEqual(actual.question.class_, RRClass.IN)

    def test_standard_A_recursive_query(self):
        actual = Query('github.com', RRType.A,
                       is_recursion_desired=True)

        self.assertEqual(actual.header.message_type, MessageType.QUERY)
        self.assertEqual(actual.header.question_count, 1)

        self.assertEqual(actual.header.query_type, QueryType.STANDARD)
        self.assertEqual(actual.header.is_authority_answer, False)
        self.assertEqual(actual.header.is_truncated, False)
        self.assertEqual(actual.header.is_recursion_desired, True)
        self.assertEqual(actual.header.is_recursion_available, False)
        self.assertEqual(actual.header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(actual.header.answer_count, 0)
        self.assertEqual(actual.header.authority_count, 0)
        self.assertEqual(actual.header.additional_count, 0)

        self.assertEqual(actual.question.name, 'github.com')
        self.assertEqual(actual.question.type_, RRType.A)
        self.assertEqual(actual.question.class_, RRClass.IN)


class TestQueryToBytes(unittest.TestCase):
    def test_standard_A_query(self):
        query = Query('google.com', RRType.A)
        id_bytes = _encode_number(query.header.identifier)

        expected = id_bytes + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\00' \
                              b'\x06google\x03com\x00\x00\x01\x00\x01'
        actual = query.to_bytes()

        self.assertEqual(expected, actual)

    def test_standard_A_recursive_query(self):
        query = Query('github.com', RRType.A,
                      is_recursion_desired=True)
        id_bytes = _encode_number(query.header.identifier)

        expected = id_bytes + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\00' \
                              b'\x06github\x03com\x00\x00\x01\x00\x01'
        actual = query.to_bytes()

        self.assertEqual(expected, actual)


class TestAnswerInit(unittest.TestCase):
    def test_one_A(self):
        header = _Header(0, MessageType.RESPONSE, 1)
        question = [
            _Question('google.com')
        ]
        a_resource_data = _AResourceData(b'\xac\xd9\x0en')
        answers = [
            _ResourceRecord('google.com', type_=RRType.A,
                            length=4, data=a_resource_data, ttl=0)
        ]
        authorities = []
        additions = []

        actual = Answer(header, question, answers, authorities, additions)

        self.assertEqual(0, actual.header.identifier)
        self.assertEqual(MessageType.RESPONSE, actual.header.message_type)
        self.assertEqual(QueryType.STANDARD, actual.header.query_type)
        self.assertEqual(False, actual.header.is_authority_answer)
        self.assertEqual(False, actual.header.is_truncated)
        self.assertEqual(False, actual.header.is_recursion_desired)
        self.assertEqual(False, actual.header.is_recursion_available)
        self.assertEqual(ResponseType.NO_ERROR, actual.header.response_type)

        self.assertEqual('google.com', actual.questions[0].name)
        self.assertEqual(RRType.A, actual.questions[0].type_)
        self.assertEqual(RRClass.IN, actual.questions[0].class_)

        self.assertEqual('google.com', actual.answers[0].name)
        self.assertEqual(RRType.A, actual.answers[0].type_)
        self.assertEqual(RRClass.IN, actual.answers[0].class_)
        self.assertEqual(0, actual.answers[0].ttl)
        self.assertEqual(4, actual.answers[0].length)
        self.assertEqual(a_resource_data.ip, actual.answers[0].data.ip)


class TestAnswerFromBytes(unittest.TestCase):
    def test_one_A(self):
        in_bytes = b'\x00\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x06google\x03com\x00\x00\x01\x00\x01' \
                   b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00' \
                   b'\x00\x04\xac\xd9\x0en'
        a_resource_data = _AResourceData(b'\xac\xd9\x0en')

        actual = Answer.from_bytes(in_bytes)

        self.assertEqual(0, actual.header.identifier)
        self.assertEqual(MessageType.RESPONSE, actual.header.message_type)
        self.assertEqual(QueryType.STANDARD, actual.header.query_type)
        self.assertEqual(False, actual.header.is_authority_answer)
        self.assertEqual(False, actual.header.is_truncated)
        self.assertEqual(False, actual.header.is_recursion_desired)
        self.assertEqual(False, actual.header.is_recursion_available)
        self.assertEqual(ResponseType.NO_ERROR, actual.header.response_type)

        self.assertEqual('google.com', actual.questions[0].name)
        self.assertEqual(RRType.A, actual.questions[0].type_)
        self.assertEqual(RRClass.IN, actual.questions[0].class_)

        self.assertEqual('google.com', actual.answers[0].name)
        self.assertEqual(RRType.A, actual.answers[0].type_)
        self.assertEqual(RRClass.IN, actual.answers[0].class_)
        self.assertEqual(0, actual.answers[0].ttl)
        self.assertEqual(4, actual.answers[0].length)
        self.assertEqual(a_resource_data.ip, actual.answers[0].data.ip)
