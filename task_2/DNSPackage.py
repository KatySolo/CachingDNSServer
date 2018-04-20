import binascii
import json
from json import JSONEncoder

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
    def __init__(self, message, qtype = "0001", qclass = "0001"):
        if not message.isdigit():
            self.QNAME = code_address(message)
        else:
            self.QNAME = message
        self.QTYPE = qtype # todo make for a various types (etc. A, NS, AAAA and so on...)
        self.QCLASS = qclass


    def createQuestion(self):
        return "".join((self.QNAME, self.QTYPE, self.QCLASS))

    def getLength(self):
        return len(self.QNAME + self.QTYPE + self.QCLASS)



class Answer:
    def __init__(self, name='', type='', cclass='', ttl=0, address='', sname = ''):
        self.NAME = name
        self.TYPE = type
        self.CLASS = cclass
        self.TTL = ttl
        self.ADDRESS = address
        self.SERVER_NAME= sname

    def __str__(self):
        if self.TYPE == 5:
            return 'Canonical name: '+ self.NAME #todo fix here cname
        elif self.TYPE == 1:
            return 'Name:\t'+self.NAME+'\nAddress: '+self.ADDRESS
        elif self.TYPE == 2:
            return 'Server name: '+ self.SERVER_NAME
        else:
            return 'Unparceble variant'

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Question):
            return {'question': o.__dict__}
        if isinstance(o, Answer):
            return {'answer': o.__dict__}
        return {'__{}__'.format(o.__class__.__name__): o.__dict__}

def decoder(dct):
    if 'QNAME' in dct:
        return Question(dct['QNAME'],dct['QTYPE'], dct['QCLASS'])
    elif 'TTL' in dct:
        return Answer(dct['NAME'],dct['TYPE'], dct['CLASS'],dct['TTL'],dct['ADDRESS'],dct['SERVER_NAME'])
    return dct



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
    if all_keys:
        return str(hex(max(all_keys) + 1))[2:].zfill(4)
    else:
        return str(hex(1))[2:].zfill(4)