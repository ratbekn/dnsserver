class DNSClientException(Exception):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Внутренняя ошибка программы")


class InvalidServerResponse(DNSClientException):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Неправильный ответ от сервера")


class InvalidAnswer(DNSClientException):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Невалидные данные для создания Answer")


class ErrorResponse(DNSClientException):
    def __init__(self, data=None):
        Exception.__init__(self, "Ответ сигнализирующий о какой-то ошибке")
        self.data = data


class ServerNotRespond(DNSClientException):
    def __init__(self, msg):
        Exception.__init__(self, "Cервер на ответил")
        self.msg = msg
