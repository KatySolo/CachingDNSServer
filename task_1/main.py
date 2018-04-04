import re
import socket
import sys
from subprocess import PIPE, Popen


# def get_info_ip(line):
#     ip_pattern = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
#     ip_addr = re.findall(ip_pattern, line)
#     num = str(line)[:4]
#     if ip_addr != []:
#         response = requests.get("http://ip-api.com/json/" + ip_addr[0])
#         answer = json.loads(response.content)
#         if (answer['status'] == 'success'):
#             as_num = re.findall(r'AS[0-9]+', answer['as'])[0]
#             country = answer['country']
#             city = answer['city']
#             print(num, ip_addr[0], city + ',' + country, as_num)
#         else:
#             print(num, ip_addr[0], 'Hidden')

def get_info_db(ip, source):
    ip_addr_bytes = bytes(ip[0].encode())
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.connect(("whois." + source + ".net", 43))
    a.send(ip_addr_bytes + b'\n')
    page = b""
    as_num = ""
    country = ""
    while 1:
        data = a.recv(4096)
        if not data:
            break
        page = page + data
    result = re.findall(r"org-type:\s+IANA", str(page))
    if result:
        return "Hidden address namespace"

    # country_reg = re.compile(r'country:\s+\w{2}', re.IGNORECASE)

    try:
        as_num = re.findall(r'AS[0-9]+', str(page))[0]
        country = re.findall(r'country:\s+(\w{2})', str(page))[0].strip()
    except Exception as e:
        try:
            country = re.findall(r'Country:\s+\w{2}', str(page))[0].split(" ").pop()
        except IndexError:
            return False

    # if source == "ripe":
    #     result = re.findall(r"NON-RIPE",str(page))
    #     if result:
    #         return False
    #     else:
    #         as_num = re.findall(r'AS[0-9]+', str(page))[0]
    #         country = re.findall(r'country:\s+(\w{2})', str(page))[0].strip()
    # elif source == "afrinic":
    #     result = re.findall(r"The following results may also be obtained via",str(page))
    #     if result:
    #         return False
    #     else:
    #         as_num = re.findall(r'AS[0-9]+', str(page))[0]
    #         country = re.findall(r'country:\s+\w{2}', str(page))[0].split(" ")[1].rstrip()
    # elif source == "apnic":
    #     result = re.findall(r"Not allocated by APNIC",str(page))
    #     result_another = re.findall(r'not allocated to APNIC',str(page))
    #     if result or result_another:
    #         return False
    #     else:
    #         as_num = re.findall(r'AS[0-9]+', str(page))[0]
    #         country = re.findall(r'country:\s+\w{2}', str(page))[0].split(" ")[1].rstrip()
    # elif source == "lacnic":
    #    result = re.findall(r"The following results may also be obtained via:",str(page))
    #    if result:
    #        return False
    #    else:
    #        as_num = re.findall(r'AS[0-9]+', str(page))[0]
    #        country = re.findall(r'country:\s+\w{2}', str(page))[0].split(" ")[1].rstrip()
    # else :
    #     # result = re.findall(r'This IP address range is not registered in the ARIN database',str(page))
    #     # if result:
    #     #     return False
    #     # else:
    #     as_num = re.findall(r'AS[0-9]+', str(page))[0]
    #     country = re.findall(r'Country:\s+\w{2}', str(page))[0].split(" ").pop()
    return as_num, country


def get_ripe_info(line):
    num = re.findall('\d{,2}\s.', line)[0].rstrip()
    ip_pattern = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
    ip_addr = re.findall(ip_pattern, line)
    if ip_addr != []:
        for source in ["ripe", "afrinic", "apnic", "lacnic", "arin"]:
            result = get_info_db(ip_addr, source)
            if result == "Hidden address namespace":
                print(num, ip_addr[0], result)
                break
            elif not result:
                continue
            else:
                if num == "":
                    print("  ", ip_addr[0], result[0], result[1])
                else:
                    print(num, ip_addr[0], result[0], result[1])
                break


def get_info(user_input):
    p = Popen(['traceroute', '-w', '5', user_input], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        if line.endswith(b"* * *\n"):
            break
        get_ripe_info(str(line))
        if not line:
            break


if __name__ == "__main__":
    user_input = sys.argv[1]
    # user_input = "66.66.66.66"
    get_info(user_input)
