import binascii


class DNSPackage:

    def __init__(self):
        self.ID = 0
        self.FLAGS = ""
        self.QDCOUNT = ""
        self.ANCOUT =""
        self.NSCOUNT = ""
        self.ARCOUNT = ""

    def createQuery (self,message):
        self.ID = 'aa aa'
        self.QUERY_FLAGS = '01 00'
        self.QDCOUNT = "00 01"
        self.ANCOUNT = "00 00"
        self.NSCOUNT = "00 00"
        self.ARCOUNT = "00 00"
        self.QNAME = code_address(message)
        self.QTYPE = "00 01"
        self.QCLASS = "00 01"
        # query_db.append((ID, {message: ""}))

        return "".join((self.ID, self.QUERY_FLAGS, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT,
                        self.QNAME, self.QTYPE, self.QCLASS)).replace(" ", "")



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
