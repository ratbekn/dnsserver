import random
import struct
from collections import namedtuple

from .dns_enums import (
    MessageType, QueryType, ResponseType, RRType,
    RRClass
)
from utils.zhuban_exceptions import (
    InvalidAnswer
)

_MAX_DOUBLE_BYTE_NUMBER = 65535


def _encode_number(number: int) -> bytes:
    """
    Кодирует целое число в 2 байта с порядком байт big-endian

    :param number: целое число, которое нужно закодировать
    :raise ValueError: если число не поместиться в 2 байта
    :return: закодированное число
    """
    if 0 <= number < _MAX_DOUBLE_BYTE_NUMBER:
        return struct.pack('!H', number)

    raise ValueError("Число не помещается в 2 байта")


def _decode_number(in_bytes: bytes) -> int:
    """
    Декодирует целое число из 2 байтового представления in_bytes

    :param in_bytes: объект bytes, содержащий число
    :return: декодированное число
    """

    return struct.unpack('!H', in_bytes)[0]


def _encode_name(name: str) -> bytes:
    """
    Кодирует строку в байты в формате предназначенном для DNS

    :param name: строка для кодирования
    :return: объект bytes содержащий строку
    """
    domains = name.split('.')
    domains_in_bytes = []
    for d in domains:
        domains_in_bytes.append(struct.pack('!B', len(d)))
        domains_in_bytes.append(d.encode())

    domains_in_bytes.append(b'\x00')

    return b''.join(domains_in_bytes)


def _decode_name(in_bytes: bytes, offset: int):
    """
    Декодирует доменное имя из байтов, содержащих DNS сообщение

    :param in_bytes: байтовое представление Query/Answer
    :param offset: индекс первого байта строки в in_bytes
    :return: namedtuple('decoded_name', ['decoded_', 'offset'])
    """
    index = offset
    offset = 0
    decoded_tokens = []
    while in_bytes[index]:
        current_byte = in_bytes[index]
        if current_byte >> 6 == 3:
            if offset == 0:
                offset = index + 2
            index = _decode_number(in_bytes[index:index + 2]) ^ (3 << 14)
        else:
            decoded_tokens.append(
                in_bytes[index + 1:index + 1 + current_byte].decode('utf-8'))
            index += current_byte + 1
    if offset == 0:
        offset = index + 1

    decoded = '.'.join(decoded_tokens)

    decoded_name = namedtuple('decoded_name', ['decoded_', 'offset'])

    return decoded_name(decoded, offset)


def _get_identifier() -> int:
    """
    Возвращает рандомный идентификатор
    :return: двубайтовое число
    """
    return random.randint(0, 65535)


class Query:
    """
    Класс для представления DNS-запроса
    """

    def __init__(self, hostname: str,
                 rr_type: RRType = RRType.A,
                 is_recursion_desired=True):
        """
        Инициализирует Query

        :param hostname: доменное имя требуемой DNS записи
        :param rr_type: тип запрашиваемой DNS записи
        :param is_recursion_desired: требуется ли рекурсия
        """
        self.header = _Header(
            _get_identifier(), MessageType.QUERY, 1, QueryType.STANDARD,
            is_recursion_desired=is_recursion_desired)

        self.question = _Question(hostname, rr_type)

    def __str__(self):  # pragma: no cover
        return (f'Header:\n\t{self.header}\n'
                f'Question:\n\t{self.question}\n')

    def to_bytes(self) -> bytes:
        """
        Кодирует Query в байты

        :return: объект bytes содержащий Query
        """

        return self.header.to_bytes() + self.question.to_bytes()

    @classmethod
    def from_bytes(cls, in_bytes):
        try:
            header, offset = _Header.from_bytes(in_bytes, 0)
            questions = []
            for _ in range(header.question_count):
                question, offset = _Question.from_bytes(in_bytes, offset)
                questions.append(question)
        except Exception as e:
            raise InvalidAnswer from e

        query = Query('')
        query.header = header
        query.question = questions[0]

        return query


class Answer:
    """
    Класс для представления ответа от DNS-сервера
    """

    def __init__(self, header, questions, answers, authorities, additions):
        """
        Инициализирует Answer

        :param _Header header: заголовок DNS-ответа
        :param list of _Question questions: DNS вопросы
        :param list of _ResourceRecord answers: DNS ответы
        :param list of _ResourceRecord authorities: авторитетные сервера
        :param list of _ResourceRecord additions: дополнительная информация
        """
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additions = additions

    def __str__(self):  # pragma: no cover
        questions = '\n\t'.join(str(q) for q in self.questions)
        answers = '\n\t'.join(
            f'{i}\n\t{a}' for i, a in enumerate(self.answers, start=1))
        authorities = '\n\t'.join(
            f'{i}\n\t{a}' for i, a in enumerate(self.authorities, start=1))
        additions = '\n\t'.join(
            f'{i}\n\t{a}' for i, a in enumerate(self.additions, start=1))
        return (f'Header:\n\t{self.header}\n'
                f'Questions:\n\t{questions}\n'
                f'Answers:\n\t{answers}\n'
                f'Authorities:\n\t{authorities}\n'
                f'Additions:\n\t{additions}\n')

    def to_bytes(self) -> bytes:
        return b''.join([
            self.header.to_bytes(),
            b''.join(question.to_bytes() for question in self.questions),
            b''.join([answer.to_bytes() for answer in self.answers]),
            b''.join([authority.to_bytes() for authority in self.authorities]),
            b''.join([addition.to_bytes() for addition in self.additions])])

    @classmethod
    def from_bytes(cls, in_bytes):
        """
        Создаёт Answer из объекта bytes, содержащего Answer

        :param bytes in_bytes: объект bytes, содержащий Answer
        :return: объект Answer, декодированный из in_bytes
        """
        try:
            header, offset = _Header.from_bytes(in_bytes, 0)
            questions = []
            for _ in range(header.question_count):
                question, offset = _Question.from_bytes(in_bytes, offset)
                questions.append(question)

            answers = []
            for _ in range(header.answer_count):
                answer, offset = _ResourceRecord.from_bytes(in_bytes, offset)
                answers.append(answer)

            authorities = []
            for _ in range(header.authority_count):
                authority, offset = _ResourceRecord.from_bytes(
                    in_bytes, offset)
                authorities.append(authority)

            additions = []
            for _ in range(header.additional_count):
                additional, offset = _ResourceRecord.from_bytes(
                    in_bytes, offset)
                additions.append(additional)
        except Exception as e:
            raise InvalidAnswer from e

        return cls(header, questions, answers, authorities, additions)


class _Header:
    """
    Класс для заголовка DNS сообщения
    """

    def __init__(
            self, identifier, message_type, question_count,
            query_type=QueryType.STANDARD, is_authority_answer=False,
            is_truncated=False, is_recursion_desired=False,
            is_recursion_available=False, response_type=ResponseType.NO_ERROR,
            answer_count=0, authority_count=0, additional_count=0):
        """
        Инициализирует Header

        :param int identifier: уникальный идентификатор
        :param MessageType message_type: тип сообщения
        :param int question_count: количество разделов с вопросами
        :param query_type: тип запроса
        :param bool is_authority_answer: является ли ответ авторитетным
        :param bool is_truncated: разделено ли сообщение на несколько частей
        :param bool is_recursion_desired: требуется ли рекурсия
        :param bool is_recursion_available: доступна ли рекурсия на сервере
        :param ResponseType response_type: тип ответа
        :param int answer_count: кол-во разделов с ответами
        :param int authority_count: кол-во разделов с авторитетными ответами
        :param int additional_count: кол-во разделов с доп. информацией
        """
        self.identifier = identifier
        self.message_type = message_type
        self.query_type = query_type
        self.is_authority_answer = is_authority_answer
        self.is_truncated = is_truncated
        self.is_recursion_desired = is_recursion_desired
        self.is_recursion_available = is_recursion_available
        self.response_type = response_type
        self.question_count = question_count
        self.answer_count = answer_count
        self.authority_count = authority_count
        self.additional_count = additional_count

    def __str__(self):  # pragma: no cover
        message_type = (f'{MessageType(self.message_type).name} '
                        f'({self.message_type})')
        query_type = f'{QueryType(self.query_type).name} ({self.query_type})'
        response_type = (f'{ResponseType(self.response_type).name} '
                         f'({self.response_type})')
        return (f'Идентификатор (ID): {self.identifier}\n\t'
                f'Тип сообщения (QR): '
                f'{message_type}\n\t'
                f'Тип запроса (OPCODE): {query_type}\n\t'
                f'Авторитетный ли ответа (AA): {self.is_authority_answer}\n\t'
                f'Обрезан ли пакет (TC): {self.is_truncated}\n\t'
                f'Требуется ли рекурсия (RD): {self.is_recursion_desired}\n\t'
                f'Доступна ли рекурсия (RA): {self.is_recursion_available}\n\t'
                f'Код ответа (RCODE): '
                f'{response_type}\n\t'
                f'Кол-во вопросов (QDCOUNT): {self.question_count}\n\t'
                f'Кол-во ответов (ANCOUNT): {self.answer_count}\n\t'
                f'Кол-во автор. ответов (NSCOUNT): {self.authority_count}\n\t'
                f'Кол-во доп. ответов (ARCOUNT): {self.additional_count}\n')

    def _encode_flags(self):
        """
        Кодирует флаги Header'а в байты

        :return: объект bytes содержащий флаги
        """

        flags = (
                (self.message_type.value << 15)
                | (self.query_type.value << 11)
                | (self.is_authority_answer << 10)
                | (self.is_truncated << 9)
                | (self.is_recursion_desired << 8)
                | (self.is_recursion_available << 7)
                | (0 << 3)
                | (self.response_type << 0)
        )

        return _encode_number(flags)

    def to_bytes(self):
        """
        Кодирует Header в байты

        :return: объект bytes содержащий Header
        """
        encoded_tokens = [
            _encode_number(self.identifier),
            self._encode_flags(),
            _encode_number(self.question_count),
            _encode_number(self.answer_count),
            _encode_number(self.authority_count),
            _encode_number(self.additional_count)
        ]

        return b''.join(encoded_tokens)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт Header из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала Header внутри Query/Answer
        :return: объект namedtuple, содержащий Header и offset
        """
        offset = beginning

        identifier_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        identifier = _decode_number(identifier_in_bytes)

        flags_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        flags = int.from_bytes(flags_in_bytes, byteorder='big')

        response_type = ResponseType(flags & 15)

        is_recursion_available = bool(flags & 0x80)

        is_recursion_desired = bool(flags & 0x100)

        is_truncated = bool(flags & 0x200)

        is_authority_answer = bool(flags & 0x400)

        flags >>= 11
        query_type = QueryType(flags & 15)
        flags >>= 4

        message_type = MessageType(flags & 1)

        qcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        qcount = _decode_number(qcount_in_bytes)

        anscount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        anscount = _decode_number(anscount_in_bytes)

        authcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        authcount = _decode_number(authcount_in_bytes)

        addcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        addcount = _decode_number(addcount_in_bytes)

        header_wrapper = namedtuple('Header', ['header', 'offset'])

        header = cls(
            identifier, message_type, qcount, query_type=query_type,
            is_authority_answer=is_authority_answer, is_truncated=is_truncated,
            is_recursion_desired=is_recursion_desired,
            is_recursion_available=is_recursion_available,
            response_type=response_type, answer_count=anscount,
            authority_count=authcount, additional_count=addcount)

        return header_wrapper(header, offset)


class _Question:
    """
    Класс для вопроса DNS сообщения
    """

    def __init__(self, name, type_=RRType.A):
        """
        Инициализирует Question

        :param name: доменное имя
        :param type_: тип запрашиваемой dns записи
        """
        self.name = name
        self.type_ = type_
        self.class_ = RRClass.IN

    def __str__(self):  # pragma: no cover
        qtype = f'{RRType(self.type_).name} ({self.type_})'
        qclass = f'{RRClass(self.class_).name} ({self.class_})'
        return (f'Доменное имя для разрешения (QNAME): {self.name}\n\t'
                f'Тип требуемой записи (QTYPE): {qtype}\n\t'
                f'Класс запроса (QCLASS): {qclass}\n')

    def to_bytes(self):
        """
        Кодирует Question сообщения в байты

        :return: объект bytes содержащий Question
        """
        encoded_tokens = [
            _encode_name(self.name),
            _encode_number(self.type_.value),
            _encode_number(self.class_.value)
        ]

        return b''.join(encoded_tokens)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт Question из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала Question внутри Query/Answer
        :return: объект namedtuple, содержащий Question и offset
        """
        name, offset = _decode_name(in_bytes, beginning)
        type_ = RRType(_decode_number(in_bytes[offset:offset + 2]))
        offset += (2 + 2)

        question_wrapper = namedtuple(
            'question_wrapper', ['question', 'offset'])

        return question_wrapper(cls(name, type_=type_), offset)


class _AResourceData:
    """
    Класс для данных DNS записи типа A (IPv4)
    """

    def __init__(self, in_bytes):
        """
        Инициализирует AResourceData

        :param bytes in_bytes: 4 байта, содержащие ip address
        """
        ip = struct.unpack('!BBBB', in_bytes)
        self.ip = '.'.join(map(str, ip))

    def __str__(self):  # pragma: no cover
        return f'IPv4 адрес (ADDRESS): {self.ip}\n'

    def to_bytes(self) -> bytes:
        return struct.pack('!BBBB', *list(map(int, self.ip.split('.'))))


class _AAAAResourceData:
    """
    Класс для данных DNS записи типа AAAA (IPv6)
    """

    def __init__(self, in_bytes):
        """
        Инициализирует AAAAResourceData

        :param bytes in_bytes: 32 байта, содержащие ip address
        """
        ip = [in_bytes[i:i + 2] for i in range(0, len(in_bytes), 2)]
        self.ip = ':'.join(map(bytes.hex, ip))

    def __str__(self):  # pragma: no cover
        return f'IPv6 адрес (ADDRESS): {self.ip}\n\t'

    def to_bytes(self) -> bytes:
        return b''.join(map(bytes.fromhex, self.ip.split(':')))


class _PTRResourceData:
    """
    Класс для данных DNS записи типа PTR
    """

    def __init__(self, in_bytes):
        """
        Инициализирует PTRResourceData

        :param bytes in_bytes: байты содержащие domain_name
        """
        self.name = _decode_name(in_bytes, 0).decoded_

    def __str__(self):  # pragma: no cover
        return f'Доменное имя (PTRDNAME): {self.name}\n'

    def to_bytes(self) -> bytes:
        return _encode_name(self.name)


class _NSResourceData:
    """
    Класс для данных DNS записи типа NS
    """

    def __init__(self, in_bytes, offset):
        """
        Инициализирует NSResourceData

        :param bytes in_bytes:
        """
        self.name = _decode_name(in_bytes, offset).decoded_

    def __str__(self):  # pragma: no cover
        return f'Авторитетный сервер разрешения имен (NSDNAME): {self.name}\n'

    def to_bytes(self) -> bytes:
        return _encode_name(self.name)


class _SOAResourceData:
    """
    Класс для данных DNS записи типа SOA
    """

    def __init__(self, in_bytes, offset):
        self.name_server, offset = _decode_name(in_bytes, offset)
        self.email_addr, offset = _decode_name(in_bytes, offset)

        serial_number = in_bytes[offset:offset + 4]
        refresh = in_bytes[offset + 4:offset + 8]
        retry = in_bytes[offset + 8:offset + 12]
        expiry = in_bytes[offset + 12:offset + 16]
        nxdomain_ttl = in_bytes[offset + 16:offset + 20]

        fmt = '!I'
        self.serial_number = struct.unpack(fmt, serial_number)[0]
        self.refresh = struct.unpack(fmt, refresh)[0]
        self.retry = struct.unpack(fmt, retry)[0]
        self.expiry = struct.unpack(fmt, expiry)[0]
        self.nxdomain_ttl = struct.unpack(fmt, nxdomain_ttl)[0]

    def __str__(self):  # pragma: no cover
        return (f'Мастер сервер зоны (MNAME): {self.name_server}\n\t\t'
                f'Почта ответсвенного за зону (RNAME): {self.email_addr}\n\t\t'
                f'Номер версии оригинальной копии зоны (SERIAL): '
                f'{self.serial_number}\n\t\t'
                f'Интервал обновления зоны (REFRESH): {self.refresh}\n\t\t'
                f'Интервал ожидания при неудачном обновлении (RETRY): '
                f'{self.retry}\n\t\t'
                f'Верхняя граница интервала, которое может пройти перед тем '
                f'как зона станет не авторитетной (EXPIRE): '
                f'{self.expiry}\n\t\t'
                f'Минимальный TTL, который должен быть экспортирован с '
                f'любой записью из зоны (MINIMUM): {self.nxdomain_ttl}\n\t\t')

    def to_bytes(self) -> bytes:
        encoded_tokens = [
            _encode_name(self.name_server),
            _encode_name(self.email_addr),
            struct.pack('!I', self.serial_number),
            struct.pack('!I', self.refresh),
            struct.pack('!I', self.retry),
            struct.pack('!I', self.expiry),
            struct.pack('!I', self.nxdomain_ttl)
        ]

        return b''.join(encoded_tokens)


class _TXTResourceData:
    """
    Класс для данных DNS записи типа TXT
    """

    def __init__(self, in_bytes, offset):
        length = struct.unpack('!B', in_bytes[offset: offset + 1])[0]
        self.text = in_bytes[offset + 1: offset + 1 + length].decode('utf-8')

    def __str__(self):  # pragma: no cover
        return f'Текст (TXT-DATA): {self.text}'

    def to_bytes(self):
        return struct.pack('!B', len(self.text)) + self.text.encode('utf-8')


class _MXResourceData:
    """
    Класс для данных DNS записи типа MX
    """

    def __init__(self, in_bytes, offset):
        self.preference = _decode_number(in_bytes[offset: offset + 2])
        self.name = _decode_name(in_bytes, offset + 2)[0]

    def __str__(self):  # pragma: no cover
        return (f'Приоритет записи (PREFERENCE): {self.preference}\n\t\t'
                f'Домен почтового сервера (EXCHANGE): {self.name}\n\t\t')

    def to_bytes(self) -> bytes:
        return b''.join([_encode_number(self.preference), _encode_name(self.name)])


class _CNAMEResourceData:
    """
    Класс для представления DNS записи типа CNAME
    """

    def __init__(self, in_bytes, offset):
        self.cname = _decode_name(in_bytes, offset).decoded_

    def __str__(self):  # pragma: no cover
        return f'Каноническое имя (CNAME): {self.cname}\n'

    def to_bytes(self) -> bytes:
        return _encode_name(self.cname)


class _ResourceRecord:
    """
    Класс для ResourceRecord
    """

    def __init__(
            self, name, type_, length, data, ttl=0,
            class_=RRClass.IN):
        """
        Инициализирует ResourceRecord

        :param str name: запрошенное доменное имя
        :param RRType type_: тип DNS записи
        :param int length: длина данных
        :param data: данные
        :param ttl: время в секундах, сколько запись может быть в кэширована
        :param RRClass class_: класс ResourceRecord
        """
        self.name = name
        self.type_ = type_
        self.class_ = class_
        self.ttl = ttl
        self.length = length
        self.data = data

    def __str__(self):  # pragma: no cover
        type_ = f'{RRType(self.type_).name} ({self.type_})'
        class_ = f'{RRClass(self.class_).name} ({self.class_})'
        return (f'Домен, которому относится эта запись (NAME): {self.name}\n\t'
                f'Тип записи (TYPE): {type_}\n\t'
                f'Класс записи (CLASS): {class_}\n\t'
                f'Время кэширования (TTL): {self.ttl}\n\t'
                f'Длина данных в байтах (RDLENGTH): {self.length}\n\t'
                f'Данные (RDATA): \n\t\t{self.data}\n\t'
                '----------------------------------\n')

    @classmethod
    def _decode_data(cls, in_bytes, type_, length, offset):
        """
        Декодирует данные ResourceRecord

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param RRType type_: тип DNS записи
        :param int length: длина данных в байтах
        :param int offset: индекс первого байта данных в in_bytes
        :return: соответствующий type_ *ResourceData
        """
        data_in_bytes = in_bytes[offset:offset + length]
        if type_ == RRType.A:
            return _AResourceData(data_in_bytes)
        elif type_ == RRType.AAAA:
            return _AAAAResourceData(data_in_bytes)
        elif type_ == RRType.PTR:
            return _PTRResourceData(data_in_bytes)
        elif type_ == RRType.NS:
            return _NSResourceData(in_bytes, offset)
        elif type_ == RRType.SOA:
            return _SOAResourceData(in_bytes, offset)
        elif type_ == RRType.TXT:
            return _TXTResourceData(in_bytes, offset)
        elif type_ == RRType.MX:
            return _MXResourceData(in_bytes, offset)
        elif type_ == RRType.CNAME:
            return _CNAMEResourceData(in_bytes, offset)

    def to_bytes(self):
        encoded_tokens = [
            _encode_name(self.name),
            _encode_number(self.type_.value),
            _encode_number(self.class_.value),
            struct.pack('!I', self.ttl),
            # _encode_number(self.length),
            _encode_number(len(self.data.to_bytes())),
            self.data.to_bytes()
        ]

        return b''.join(encoded_tokens)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт ResourceRecord из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала ResourceRecord внутри Query/Answer
        :return: объект namedtuple, содержащий ResourceRecord и offset
        """
        name, offset = _decode_name(in_bytes, beginning)

        type_ = RRType(_decode_number(in_bytes[offset:offset + 2]))
        offset += 2

        class_ = RRClass(_decode_number(
            in_bytes[offset:offset + 2]))
        offset += 2

        ttl = struct.unpack('!I', in_bytes[offset:offset + 4])[0]
        offset += 4

        length = _decode_number(in_bytes[offset:offset + 2])
        offset += 2

        data = cls._decode_data(in_bytes, type_, length, offset)
        offset += length

        rr_wrapper = namedtuple('rr_wrapper', ['resource_record', 'offset'])

        return rr_wrapper(cls(name, type_, length, data, ttl, class_), offset)
