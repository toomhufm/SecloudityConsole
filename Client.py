import threading
import socket,ssl
import argparse
import hashlib , binascii, base64
import sys, os , pickle
import json
import requests
import datetime
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from Crypto.Cipher import AES
from tabulate import tabulate
from getpass import getpass
from string import printable

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('20.205.46.109', 1337))
server_ip = '20.205.46.109'

# Database=========================================
url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-zbetm/endpoint/data/v1/action/"
apikey = "hSl7T5DEqopdOtu6JYzUI4taQ6BwUmTSNRtBl2VXwIwpnMfjv13fsnpMxdgQltSX"
headers = {
  'Content-Type': 'application/json',
  'Access-Control-Request-Headers': '*',
  'api-key': apikey,
} 

client_ssl = ssl.wrap_socket(
    client, 
    ca_certs='../ssl/20.205.46.109.crt',
    )

# client_ssl.write(b"Hello Server!")
def Banner():
    banner = """
                  ██████                
                ██      ██              
              ██          ████          
            ██              ▒▒██        
        ████▒▒                ██        
  ██████      ▒▒            ▒▒▒▒████    
██▒▒            ▒▒        ▒▒      ▒▒██  
██▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒▒▒          ▒▒██
  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██
    ████████▓▓████████████████████████  

                SECLOUDITY
    use /help for available commands
    """
    print(banner)

def Help():
    message = """
    ========================== HELP MENU ==========================
    /register                         : register
    /login                            : login
    /verify                           : verify your account 
    /key                              : get your private key
    /upload                           : choose file to upload
    /download                         : download files
    /search [option : -d,-o,-n]       : search files
    -d : search by upload date
    -o : search by file owner name
    -n : search by file name
    ===============================================================
    """
    print(message)
    
def upload(content, filename, username):
    action = url + "insertOne"
    payload = json.dumps({
    "collection": "Documents",
    "database": "CompanyStorage",
    "dataSource": "Cluster0",
    "document": 
    {
        "filename":filename + '.scd',
        "owner": username,
        "content":content,
        "upload_date":str(datetime.date.today()),
        "sha256" : binascii.hexlify(hashlib.sha256(bytes.fromhex(content)).digest()).decode()
        
    }
    })
    response = requests.request("POST", action, headers=headers, data=payload)
    result = response.text 
    if(result):
        return True 
    else:
        return False

def download(filename,path):
    action = url + "findOne"
    payload = json.dumps({
    "collection": "Documents",
    "database": "CompanyStorage",
    "dataSource": "Cluster0",
    "filter": {"filename":filename},
    "projection": 
    {
        "content":1,
        "sha256":1,
        "filename":1
    }
    })
    response = requests.request("POST", action, headers=headers, data=payload)
    result = json.loads(response.text)['document'] 
    if(result):
        filename = result['filename'].replace('.scd','')
        ctx = result['content']
        content = cpabe.ABEdecryption(ctx,publickey,privatekey)
        if(content):
            with open(path+'/'+filename,'wb') as f:
                f.write(content)
            return True
        else:
            return -1
    else:
        return False    

def ObfucasteAndHash(password):
    length = len(password)
    res = ""
    for i in range(length):
      res += printable[ord(password[i]) % 94]
    obj = hashlib.sha256(res.encode()).digest()
    return binascii.hexlify(obj).decode()

def HandleSearch(message):
    option = ['-d','-o','-n']
    msg = '/search'
    for i in message.split(' '):
        if i in option:
            if(i == '-d'):
                print("Upload date format DMY\nexample : 2023-06-01 ")
                upload_date = input('Enter upload date : ')
                msg += f' -d {upload_date}'
            if(i == '-o'):
                owner_name = input('Enter owner username :  ')
                msg += f' -o {owner_name}'
            if(i == '-n'):
                filename = input('Enter file name : ')
                msg += f' -n {filename}'
    return msg

def Search(message):
    option = ['-d','-n','-o']
    message = message.split(' ')
    op = [0]*3
    for msg in message:
        if msg in option:
            if(msg == '-d'):
                op[0] = message[message.index(msg) + 1]
            if(msg == '-n'):
                op[1] = message[message.index(msg) + 1]
            if(msg == '-o'):
                op[2] = message[message.index(msg) + 1]
    filter = {}
    if(op[0]):
        filter['upload_date'] = op[0]
    if(op[1]):
        filter['filename'] = op[1]
    if(op[2]):
        filter['owner'] = op[2]
    action = url + "find"
    payload = json.dumps({
        "collection": "Documents",
        "database": "CompanyStorage",
        "dataSource": "Cluster0",
        "filter" : filter,
        "projection":{
            "filename":1,
            "owner":1,
            "upload_date":1,
            "sha256":1
        }
    })    
    
    response = requests.request("POST", action, headers=headers, data=payload)
    result = json.loads(response.text)['documents']
    if(result):
        to_print = len(result)*[0]
        for i in range(len(result)):
            to_print[i] = result[i]['_id'], result[i]['filename'],result[i]['owner'],result[i]['upload_date'],result[i]['sha256']
        print(tabulate(to_print,headers=['ID','File Name','Owner','Upload Date','SHA256'],tablefmt='grid'))
    else:
        print("[!] Found 0 file")

def client_receive():
    global LogedIn
    global Verified
    global publickey
    global privatekey
    while True:
        try:
            message = client_ssl.read(len=4096*2)
            if(message):
                if(message == b"Loged in."):
                    LogedIn = True
                    print(f"[NOTI] {message.decode()}\nPress Enter to continue...")
                elif(message == b"@VERIFIED"):
                    Verified = True
                elif(message.startswith(b'@Verified!') or message.startswith(b'You already verified!')):
                    Verified = True
                    print(f"[NOTI] You are Verified!\nPress Enter to continue...")
                elif(message.startswith(b"@PUBLIC")):
                    publickey = message.split(b'@PUBLIC')[1].decode()
                    publickey = cpabe.bytesToObject(bytes.fromhex(publickey),cpabe.groupObj)
                elif(message.startswith(b"@PRIVATE")):
                    privatekey = message.split(b"@PRIVATE")[1].decode()
                    privatekey = cpabe.bytesToObject(bytes.fromhex(privatekey),cpabe.groupObj)
                    print(f"[NOTI] Key received\nPress Enter to continue...")
                else:
                    print(f"[NOTI] {message.decode()}\nPress Enter to continue...")
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    

def handle_input(message : str):
    global USERNAME
    if(message):
        if message.startswith('/help'):
            Help() 
            return None
        elif message.startswith('/register'):
            username = input("[+] Enter username : ")
            password = getpass("[+] Enter password : ")
            if(len(password) < 8):
                print("[ERROR] : Password must be longer than 8")
                return None
            conf_password = getpass("[+] Confirm password : ")
            if(conf_password == password):
                return f"/register {username} {ObfucasteAndHash(password)}".encode()
            else:
                print("[ERROR] : Password did not match!")
                return None
        elif message.startswith('/login'):
            username = input("[+] Enter username : ")
            password = getpass("[+] Enter password : ")    
            USERNAME = username
            return f"/login {username} {ObfucasteAndHash(password)}".encode()
        if(LogedIn):
            if(message.startswith("/verify")):
                fullname = input("[+] Enter fullname : ")
                birth = input("[+] Enter day of birth : ")
                cccd = input("[+] Enter cccd : ")
                return f"/verify {fullname} {birth} {ObfucasteAndHash(cccd)}".encode() 
            if(Verified):      
                if(message.startswith("/key")):
                    return message.encode()
                elif(message.startswith("/upload")):
                    path = input("[+] Path to File : ").strip()
                    policy = input("[+] Policy : ").strip()
                    content = cpabe.ABEencryption(path,publickey,policy)
                    content = binascii.hexlify(content).decode()
                    filename = path.split('/')[-1]
                    if(upload(content,filename,USERNAME)):
                        print("[NOTI] File Uploaded")
                    else:
                        print("[NOTI] Failed to upload file")
                    return None 
                elif(message.startswith("/download")):
                    filename = input("Enter file name : ")
                    path = input("Enter path to save file : ")
                    state = download(filename,path)
                    if(state and state != -1):
                        print(f"[NOTI] : File downloaded at {path}")
                    elif(state == -1):
                        print("[NOTI] : You are not allowed to download this file!")
                    else:
                        print("[NOTI] : File not existed")
                    return None 
                elif(message.startswith("/search")):
                    _message = message.split(' ')
                    l = len(_message)
                    for i in range(l):
                        if (l == 1):
                            print("[!] : No option found!")
                            return None
                        elif(l > 4):
                            print("[!] : Too many options!")
                        else:
                            msg = HandleSearch(message)
                            Search(msg)
                            return None       
                    return None 
            else:
                print("[!] : You must verified first")
                return None                 
        else:
            print("[!] : You must login first")
            return None
    else: 
        return None
def client_send():
    while True:
        message = handle_input(input(">> "))
        if(message):
            client_ssl.write(message)
            # print(message)

def main():
    listen = threading.Thread(target=client_receive)
    listen.start()
    sendthread = threading.Thread(target=client_send)
    sendthread.start()
if __name__ == '__main__':
    Banner()
    global LogedIn
    global Verified
    global publickey
    global privatekey
    global USERNAME
    publickey = b""
    privatekey = b""
    Verified = False
    LogedIn = False
    USERNAME = ""
    main()
