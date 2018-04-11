import binascii
from task_2.database import queries_db


class SuspiciousDNSError (Exception):
    pass


class DNSPackage:

    def __init__(self):
        self.ID = 0
        self.FLAGS = None
        self.QDCOUNT = None
        self.ANCOUNT = None
        self.NSCOUNT = None
        self.ARCOUNT = None


    def createQuery (self,message):
        self.ID = generate_id()
        self.QUERY_FLAGS = '01 00'
        self.QDCOUNT = "00 01" # todo think about case of multiply questions(??)
        self.ANCOUNT = "00 00"
        self.NSCOUNT = "00 00"
        self.ARCOUNT = "00 00"

        self.QUESTION_BLOCK = Question(message)
        queries_db[self.ID] = self.QUESTION_BLOCK

        question = self.QUESTION_BLOCK.createQuestion()
        return "".join((self.ID, self.QUERY_FLAGS, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT,question)).replace(" ", "")

    def checkResponseValidity(self, id):
        try:
            self.QUESTION = queries_db[id]
        except LookupError as e:
            return False
        return True

    def createResponse(self):
        self.QUERIES = []
        self.ANSWERS = []
        self.AUTHORITY_RECORDS = []
        self.ADDITIONAL_RECORDS = []

class Question:

    def __init__(self, message):
        self.QNAME = code_address(message)
        self.QTYPE = "00 01" # todo make for a various types (etc. A, NS, AAAA and so on...)
        self.QCLASS = "00 01"

    def createQuestion(self):
        return "".join((self.QNAME, self.QTYPE, self.QCLASS))

    def getLength(self):
        return len(self.QNAME + self.QTYPE + self.QCLASS)

class Answer:
    def __init__(self):
        self.NAME = ""
        self.TYPE = ""
        self.CLASS = ""
        self.TTL = 0
        self.ADDRESS = ""
        self.SERVER_NAME=""



def code_address(message):
    """
    Кодирует адрес для отправки запроса
    :param message: адрес для колирования
    :return: закодированный адрес
    """
    splitted_msg = message.split('.')
    result = ""
    for p in splitted_msg:
        part_len = str(hex(len(p)))
        result += part_len[2:].zfill(2)
        for b in p:
            result += str((binascii.hexlify(bytes(b,encoding='utf-8'))))[2:-1]
    result += '00'
    global question_len
    question_len = len(result)
    return result

def decode_address(message):
    """
    Декодирует из ответа из 16тиричного представления в строку
    :param message: закодированное сообщение
    :return: адрес из ответа
    """
    result = [int(message[i:i+2],16) for i in range(0, len(message), 2)]
    result_str = ''
    start_pos = 0

    while (True):
        for i in range(result[start_pos]):
            result_str += chr(result[start_pos+i+1])
        result_str += '.'
        start_pos = len(result_str)
        if (start_pos == len(result)) :
            break

    return result_str[:-1]

def generate_id():
    all_keys = set(queries_db.keys())
    return str(hex(max(all_keys) + 1))[2:].zfill(4)