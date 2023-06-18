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
from MyCrypto.curve25519 import *
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
    /views                            : view files info
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
        "filename":filename,
        "owner": username,
        "content":content,
        'upload_date':str(datetime.date.today())
    }
    })
    r = requests.request("POST", action, headers=headers, data=payload)
    
def ObfucasteAndHash(password):
    length = len(password)
    res = ""
    for i in range(length):
      res += printable[ord(password[i]) % 94]
    obj = hashlib.sha256(res.encode()).digest()
    return binascii.hexlify(obj).decode()

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
                    publickey = message.split(b'@PUBLIC')[1]
                elif(message.startswith(b"@PRIVATE")):
                    privatekey = message.split(b"@PRIVATE")[1]
                    print(f"[NOTI] Key received\nPress Enter to continue...")
                else:
                    print(f"[NOTI] {message.decode()}\nPress Enter to continue...")
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    

def handle_input(message : str):
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
                    path = input("[+] Path to File : ")
                    policy = input("[+] Policy : ")
                    
                    return None 
                elif(message.startswith("/download")):
                    return None 
                # elif(message.startswith("/search")):
                #     message = message.split(' ')
                #     l = len(message)
                #     for i in range(l):
                #         if (l == 1):
                #             print("[NOTI] No option found")
                #             return None
                #         elif(l == 2):
                #             if(message[i]):
                #     #https://viblo.asia/p/viet-cli-trong-python-de-dang-voi-argparse-XL6lA2ar5ek\
                #     #https://docs.python.org/3/library/argparse.html           
                #     return None 
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
    publickey = b""
    privatekey = b""
    Verified = False
    LogedIn = False
    main()
