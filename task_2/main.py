import binascii
import socket
import unicodedata

import re

from task_2.DNSPackage import DNSPackage, SuspiciousDNSError

dns_cache = []
question_len = 0

def send_dns_query(message, address):
    """
    Метод для отсылки DNS запроса
    :param message: искомый адрес
    :param address: адрес DNS сервера
    :return: полученный от DNS сервера ответ
    """

    query = DNSPackage().createQuery(message)
    # print(query)
    server_address = (address, 53)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(query), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")

def parse_response(response_data):
    """
    Метод разблра ответа от DNS сервера
    :param response_data: ответ от сервера в 16тиричном представлении
    :return: none
    """
    id = response_data[:4]
    response = DNSPackage()
    validResponse = response.checkResponseValidity(id)

    if not validResponse:
        raise SuspiciousDNSError("Suspicious response. Probably, server was hacked.")

    response.ID = id
    response.RESPONSE_FLAGS = response_data[4:8]
    response.QDCOUNT = int(response_data[8:12], 16)
    response.ANCOUNT = int(response_data[12:16], 16)
    response.NSCOUNT = int(response_data[16:20], 16)
    response.ARCOUNT = int(response_data[20:24], 16)



    question_fin = 24+question_len

    response.QUESTION = response_data[24: question_fin]
    response.QTYPE = response_data[question_fin: question_fin + 4]
    response.QCLASS = response_data[question_fin + 4: question_fin + 8]

    # если больше одного ответа, то начать разбор
    # if resp.ANCOUNT > 0:
    for i in range(response.ANCOUNT):
        response_start = response_data[question_fin + 8:]
        # if response_start[:response_start.ndex('0001')] == "c0":
        name_length = response_start.find('0001')
        if (response_start[name_length+4:].find('0001') != -1):
            name_length = response_start.find('0001',name_length+4)
        # todo extract correctly name length (find second 0001 group)
        RESPONSE_NAME = extaract_address(response_data, response_start[:name_length - 4])
        print('name = ',RESPONSE_NAME)
        name_end = response_start[name_length-4:]
        # print (response, RESPONSE_NAME, name_end)
        TYPE = int(name_end[:4],16)
        print('type =',TYPE)
        class_note = int(name_end [4:8],16)
        print('class=', class_note)
        TTL = int (name_end[8:16],16)
        print('ttl=',TTL)
        data_length = int(name_end[16:20],16)
        ADDRESS = decode_ip_address(name_end[20:28])
        print('address = ',ADDRESS)

    # print (ID,RESPONSE_FLAGS,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT, QUESTION, QTYPE, QCLASS)
try:
    response = send_dns_query("example.com", "8.8.8.8")
    print(response)
except OSError as e:
    print ('INTERNETA NETY')

# new_data = parse_response(response)
