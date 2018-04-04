import binascii
import socket
import unicodedata

import re

query_db = []
question_len = 0

def code_address(message):
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
    result = [int(message[i:i+2],16) for i in range(0, len(message), 2)]
    result_str = ''
    # todo rewrite to domain tree
    #todo FIX THIS PART

    # for i in range(len(result)):
    #     if result[i]>96:
    #         result_str += chr(result[i])
    #     elif i<0:
    #         continue
    #     else:
    #         if result[i-1] > 96:
    #             result_str +=


    # return result_str[1:]
    # print (result)
    # print (ord('a'))
    result_str = ''
    start_pos = 0

    while (True):
        for i in range(result[start_pos]):
            result_str += chr(result[start_pos+i+1])
        start_pos = len(result_str) + 1
        if (start_pos == len(result)) :
            break
        else:
            result_str += '.'

    return result_str

def decode_ip_address(param):
    result = [str(int(param[i:i + 2], 16)) for i in range(0, len(param), 2)]
    return ".".join(result)
    pass

def send_udp_message(message, address, port):
    ID = 'aa aa'
    QUERY_FLAGS = '01 00'
    QDCOUNT = "00 01"
    ANCOUNT = "00 00"
    NSCOUNT = "00 00"
    ARCOUNT = "00 00"

    QNAME = code_address(message)
    QTYPE = "00 01"
    QCLASS = "00 01"

    query_db.append((ID, {message:""}))
    message = "".join((ID,QUERY_FLAGS,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT,QNAME,QTYPE,QCLASS)).replace(" ","")
    # print (message)
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")





def extaract_address(response, address):
    response_address = ''
    valuable_bits = bin(int(address[:2], 16))[2:]
    if  valuable_bits[:2] == '11':
        link_str = valuable_bits[2:] + bin(int(address[2:], 16))[2:]
        link_int = int(link_str,2)*2
        print ('link')
        address_start = response[link_int:]
        end_address_mark = address_start.index('00')

        name = decode_address(address_start[:end_address_mark])

        return name
    else:
        print ("non-link")
        name = decode_address(address)
        return name

    # print (address)


def parse_response(response):
    # print (response)
    ID = response[:4]
    RESPONSE_FLAGS = response[4:8]
    QDCOUNT = int(response[8:12],16)
    ANCOUNT = int(response[12:16],16)
    NSCOUNT = int(response[16:20],16)
    ARCOUNT = int(response[20:24],16)
    question_fin = 24+question_len

    QUESTION = response[24: question_fin]
    QTYPE = response[question_fin: question_fin + 4]
    QCLASS = response[question_fin+4: question_fin+8]
    # если больше одного ответа, то начать разбор
    if ANCOUNT > 0:
        response_start = response[question_fin+8:]
        # if response_start[:response_start.ndex('0001')] == "c0":
        name_length = response_start.find('0001')
        if (response_start[name_length+4:].find('0001') != -1):
            name_length = response_start.find('0001',name_length+4)
        # todo extract correctly name length (find second 0001 group)
        RESPONSE_NAME = extaract_address(response, response_start[:name_length-4])
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

        # print (TYPE,class_note,TTL,data_length,ADDRESS)

        # RESPONSE_NAME = decode_response_name(response, )
        # print (rest)








    # print (ID,RESPONSE_FLAGS,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT, QUESTION, QTYPE, QCLASS)


# def format_hex(hex):
#     """format_hex returns a pretty version of a hex string"""
#     octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
#     pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
#     return "\n".join(pairs)


# message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
# "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"

response = send_udp_message("ns1.vk.com","8.8.8.8", 53)
new_data = parse_response(response)
# print (response)
