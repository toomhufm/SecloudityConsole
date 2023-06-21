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

from pymongo import MongoClient
import gridfs 
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import gridfs

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('20.205.46.109', 1337))
server_ip = '20.205.46.109'

client_ssl = ssl.wrap_socket(
    client, 
    ca_certs='../ssl/20.205.46.109.crt',
    )
# Database 

# Replace the placeholder with your Atlas connection string
uri = "mongodb+srv://storage:admin123@cluster0.hjzxwtv.mongodb.net/?retryWrites=true&w=majority"

# Set the Stable API version when creating a new client
client = MongoClient(uri, server_api=ServerApi('1'))
dbname = "CompanyStorage"       
db = client[dbname]         
file_collection = db['fs.files']
fs = gridfs.GridFS(file_collection.database)
# ================================================================================================

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
    /search [option : -d,-o,-e]       : search files
    -d : search by upload date
    -o : search by file owner name
    -n : search by file extension
    ===============================================================
    """
    print(message)
    
def upload(content, file_name, username):
    dup = fs.find_one(filter={"filename":file_name})
    file_extension = file_name.replace('.scd','').split('.')[-1]
    if(not dup):
        hash = binascii.hexlify(hashlib.sha256(content).digest()).decode()
        fs.put(content,filename=file_name,owner=username,extension=file_extension,upload_date=str(datetime.date.today()),sha256=hash)
        return 1
    else:
        return -1

def download(file_name,path):
    file = fs.find_one({"filename": file_name})
    if file:
        file_name = file_name.replace('.scd','')
        enc = file.read().decode()
        dec = cpabe.ABEdecryption(enc,publickey,privatekey)
        if(dec):
            with open(path+'/'+file_name, "wb") as f:
                f.write(dec)
        else:
            return -1
        return 1
    else:
        return -1
 

def ObfucasteAndHash(password):
    length = len(password)
    res = ""
    for i in range(length):
      res += printable[ord(password[i]) % 94]
    obj = hashlib.sha256(res.encode()).digest()
    return binascii.hexlify(obj).decode()

def HandleSearch(message):
    option = ['-d','-o','-e']
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
            if(i == '-e'):
                filename = input('Enter file extension : ')
                msg += f' -e {filename}'
    return msg

def Search(message):
    option = ['-d','-o','-e']
    message = message.split(' ')
    op = [0]*3
    for msg in message:
        if msg in option:
            if(msg == '-d'):
                op[0] = message[message.index(msg) + 1]
            if(msg == '-e'):
                op[1] = message[message.index(msg) + 1]
            if(msg == '-o'):
                op[2] = message[message.index(msg) + 1]
    filter = {}
    if(op[0]):
        filter['upload_date'] = op[0]
    if(op[1]):
        filter['extension'] = op[1]
    if(op[2]):
        filter['owner'] = op[2]
    result = file_collection.find(filter)
    to_print = []
    for i, doc in enumerate(list(result), start=0):
        to_print.append([doc['_id'], doc['filename'],doc['owner'],doc['upload_date'],doc['sha256']])
    if(len(to_print) > 0):
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
                    content = binascii.hexlify(content)
                    filename = path.split('/')[-1] + '.scd'
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
