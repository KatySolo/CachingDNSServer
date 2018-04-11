import binascii
import socket
from task_2.database import queries_db,answers_db,domains_db
import unicodedata
from functools import reduce

import re

from task_2.DNSPackage import DNSPackage, SuspiciousDNSError, Answer, decode_address

dns_cache = []

question_len = 0
isFlag = False


def add_new_address(link_int, new_address):
    parts = new_address.split('.')
    # prev_part = ""
    address = new_address
    next_addr = new_address
    domains = domains_db.values()
    pointer = 0
    for i in parts:
        if not next_addr in domains:
        # address = address[pointer:]
            domains_db[pointer*2+link_int] = address[pointer:]
            pointer = pointer + next_addr.find('.') + 1
            next_addr = address[pointer:]
        else:
            break

def extaract_address(response, address):
    """
    Метод извлечения адреса из ответа
    :param response: полный ответ от сервера
    :param address: адрес или ссылка на него в 16тиричном формате
    :return: адрес IPv4 в виде строки
    """
    name = []
    while (address):
        valuable_bits = bin(int(address[:2], 16))[2:].zfill(8)
        if  valuable_bits[:2] == '11':
            link_str = valuable_bits[2:] + bin(int(address[2:], 16))[2:]
            link_int = int(link_str,2)*2
            print ('link')
            address_start = response[link_int:]
            if link_int not in domains_db.keys():
                end_address_mark = address_start.index('00')
                new_address = decode_address(address_start[:end_address_mark])
                add_new_address(link_int,new_address)
                domains_db[link_int] = new_address
                name.append(new_address)
            else:
                name.append(domains_db[link_int])

            address = address[4:]
        else:
            print ("non-link")
            length = int(address[:2], 16)*2
            name.append(decode_address(address[:length+2]))
            address = address[length+2:]
    return '.'.join(name)

def decode_ip_address(address):
    """
    Декодирование IP адреса из 16тиричного представление
    :param address: адрес ввиде последовательности 16тиричной
    :return: IPv4 адрес строкой
    """
    result = [str(int(address[i:i + 2], 16)) for i in range(0, len(address), 2)]
    return ".".join(result)


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
    Метод разбора ответа от DNS сервера
    :param response_data: ответ от сервера в 16тиричном представлении
    :return: none
    """
    id = response_data[:4]
    response = DNSPackage()
    validResponse = response.checkResponseValidity(id)

    if not validResponse:
        raise SuspiciousDNSError("Suspicious response. Probably, server was hacked.")

    response.ID = id
    response.FLAGS = response_data[4:8]
    response.QDCOUNT = int(response_data[8:12], 16)
    response.ANCOUNT = int(response_data[12:16], 16)
    response.NSCOUNT = int(response_data[16:20], 16)
    response.ARCOUNT = int(response_data[20:24], 16)
    response.createResponse()
    response.QUESTION = queries_db[response.ID]
    response.QUERIES.append(response.QUESTION)
    response_start_index = 22 + response.QUESTION.getLength()

    # answers
    for i in range(response.ANCOUNT):
        answer = Answer()
        response_start = response_data[response_start_index:]

        name_length = response_start.find('00')
        if (response_start[name_length + 4:].find('0001') != -1):
            name_length = response_start.find('0001',name_length+4)

        answer.NAME = extaract_address(response_data, response_start[:name_length - 4])
        name_end_index = response_start[name_length-4:]
        answer.TYPE = int(name_end_index[:4],16)
        answer.CLASS= int(name_end_index [4:8],16)
        answer.TTL = int (name_end_index[8:16],16)
        if answer.TYPE != 5:
            answer.ADDRESS = decode_ip_address(name_end_index[20:28])
        response_start_index = response_start_index+name_length+24
        response.ANSWERS.append(answer)

    # authoritative name servers
    for i in range(response.NSCOUNT):
        answer = Answer()
        response_start = response_data[response_start_index:]

        # name_length = response_start.find('00')
        # if (response_start[name_length + 4:].find('0001') != -1):
        #     name_length = response_start.find('0001',name_length+4)

        answer.NAME = extaract_address(response_data, response_start[:4])
        name_end_index = response_start[4:]
        answer.TYPE = int(name_end_index[:4],16)
        answer.CLASS= int(name_end_index [4:8],16)
        answer.TTL = int (name_end_index[8:16],16)
        name_server_len = int (name_end_index[16:20],16)
        server_name_codded = name_end_index[20: 20+name_server_len*2]
        server_name_index = response_data.index(name_end_index[20:])
        answer.SERVER_NAME = extaract_address(response_data,server_name_codded)
        add_new_address(server_name_index, answer.SERVER_NAME)

        response_start_index = response_start_index+len(server_name_codded)+24
        response.AUTHORITY_RECORDS.append(answer)

    #additional records
    for i in range(response.ARCOUNT):
        answer = Answer()
        response_start = response_data[response_start_index:]

        answer.NAME = extaract_address(response_data, response_start[:4])
        name_end_index = response_start[4:]
        answer.TYPE = int(name_end_index[:4], 16)
        answer.CLASS = int(name_end_index[4:8], 16)
        answer.TTL = int(name_end_index[8:16], 16)

        if answer.TYPE != 5:
            answer.ADDRESS = decode_ip_address(name_end_index[20:28])
        response_start_index = response_start_index + 8 + 24
        response.ADDITIONAL_RECORDS.append(answer)
    answers_db.append(response)

try:
    #response = send_dns_query("example.com", "8.8.8.8")
    add_new_address(24,"www.e1.ru")
    response = send_dns_query('www.e1.ru', 'ns1.e1.ru')
    parse_response(response)
    a = 2
    # print (answers_db)
except OSError as e:
    print ('INTERNETA NETY')

# new_data = parse_response(response)

