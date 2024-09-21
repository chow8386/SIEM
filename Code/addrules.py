
import requests
from bs4 import BeautifulSoup
import splunksearch
from argparse import ArgumentParser


def getCsrf(respone):
    soup = BeautifulSoup(respone.content, 'html.parser')
    csrf_token = soup.find('input', {'name': '__csrf_magic'}).get('value')
    return csrf_token

def apply_rule(cookie):
    respone = session.get(f'http://{hostname}/firewall_rules.php',cookies=cookie)
    csrf_token = getCsrf(respone)
    payload = {
    "__csrf_magic": csrf_token,
    "apply": "Apply Changes"
    }

    session.post(f'http://{hostname}/firewall_rules.php', data=payload)


def fire_reules_edit_bruteforce(csrf_token, cookie):
    query = 'search index="writelogs" source="WinEventLog:Security" EventCode=4625 Logon_Type=3 | bin _time span=5m | stats count by _time, ComputerName, Source_Network_Address | where count >= 100 '
    splunk = splunksearch.SplunkSearch(query)
    listIP = splunk.create_seach()
    for ip in listIP:      
        new_rule_data = {
                "__csrf_magic": csrf_token,
                "type": "block",
                "interface": "opt1",
                "ipprotocol": "inet",
                "proto": "any",
                "icmptype[]": "any",
                "srctype": "single",
                "src": ip,
                "dsttype": "any",
                "descr": "",
                "dscp": "",
                "tag": "",
                "tagged": "",
                "max": "",
                "max-src-nodes": "",
                "max-src-conn": "",
                "max-src-states": "",
                "max-src-conn-rate": "",
                "max-src-conn-rates": "",
                "statetimeout": "",
                "statetype": "keep state",
                "vlanprio": "",
                "vlanprioset": "",
                "sched": "",
                "gateway": "",
                "dnpipe": "",
                "pdnpipe": "",
                "ackqueue": "",
                "defaultqueue": "",
                "after": "-1",
                "ruleid": "",
                "save": "Save"
            }

        add_rule_response = session.post(f'http://{hostname}/firewall_rules_edit.php?if=opt1&after=-1', data=new_rule_data)
        apply_rule(cookie)

def fire_reules_edit_scanport(csrf_token, cookie):
    query = 'search index="pfsense" dst_ip = "192.168.40.10" | bin _time span=5m | stats dc(dst_port) as number_port by Source_Network_Address | where number_port > 300'
    splunk = splunksearch.SplunkSearch(query)
    listIP = splunk.create_seach()
    for ip in listIP:      
        new_rule_data = {
                "__csrf_magic": csrf_token,
                "type": "block",
                "interface": "opt1",
                "ipprotocol": "inet",
                "proto": "any",
                "icmptype[]": "any",
                "srctype": "single",
                "src": ip,
                "dsttype": "any",
                "descr": "",
                "dscp": "",
                "tag": "",
                "tagged": "",
                "max": "",
                "max-src-nodes": "",
                "max-src-conn": "",
                "max-src-states": "",
                "max-src-conn-rate": "",
                "max-src-conn-rates": "",
                "statetimeout": "",
                "statetype": "keep state",
                "vlanprio": "",
                "vlanprioset": "",
                "sched": "",
                "gateway": "",
                "dnpipe": "",
                "pdnpipe": "",
                "ackqueue": "",
                "defaultqueue": "",
                "after": "-1",
                "ruleid": "",
                "save": "Save"
            }

        add_rule_response = session.post(f'http://{hostname}/firewall_rules_edit.php?if=opt1&after=-1', data=new_rule_data)
        apply_rule(cookie)

def fire_rules(cookie):
    respone = session.get(f'http://{hostname}/firewall_rules_edit.php?if=opt1&after=-1',cookies=cookie)
    csrf_token = getCsrf(respone)
    if args.bruteforce:
        fire_reules_edit_bruteforce(csrf_token, cookie)
    else: 
        fire_reules_edit_scanport(csrf_token, cookie)


def login_to_pfsense(hostname, username, password):
    # Tạo session để duy trì trạng thái của phiên
    

    # Truy cập trang đăng nhập để lấy CSRF token
    login_page = session.get(f'http://{hostname}')  
    csrf_token = getCsrf(login_page)

    # Dữ liệu đăng nhập và CSRF token
    login_data = {
        '__csrf_magic': csrf_token,
        'usernamefld': username,
        'passwordfld': password,
        'login': 'Sign In'
    }

    # Gửi yêu cầu đăng nhập
    login_response = session.post(f'http://{hostname}', data=login_data)
    # Kiểm tra xem đăng nhập có thành công không
    if 'Dashboard' in login_response.text:
        print("Đăng nhập thành công!")
        cookie = session.cookies.get_dict()
        fire_rules(cookie)
        
        
        
    else:
        print("Đăng nhập thất bại!")
parser = ArgumentParser()
parser.add_argument('-b', '--bruteforce', action='store_true')
parser.add_argument('-s', '--scanport', action='store_true')
args = parser.parse_args()

hostname = '192.168.40.100'
username = 'admin'
password = 'pfsense'
session = requests.Session()


login_to_pfsense(hostname, username, password)
