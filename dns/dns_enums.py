from enum import IntEnum, unique


@unique
class MessageType(IntEnum):
    QUERY = 0
    RESPONSE = 1


@unique
class QueryType(IntEnum):
    STANDARD = 0
    INVERSE = 1
    STATUS = 2


@unique
class ResponseType(IntEnum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


@unique
class RRType(IntEnum):
    A = 1
    NS = 2
    AAAA = 28
    CNAME = 5
    SOA = 6
    WKS = 11
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AXFR = 252


@unique
class RRClass(IntEnum):
    IN = 1
