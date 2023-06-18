import socket
import ssl
import threading
import random
import base64
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
import os
import binascii
from Crypto.Cipher import AES
import hashlib
from datetime import datetime
import requests,json
import subprocess
# Initialize Server Socket
IP = '0.0.0.0'
PORT = 1337
ENDPOINT = (IP,PORT)
clients = []
session = []
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ENDPOINT)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.listen()

# Decrypt server secret key with TPM
cmd = "./unseal.sh"
key = subprocess.check_output(cmd,shell=True)
key = bytes.fromhex(key.decode().strip())

def UnSeal(path,key):
    ctx = open(path,'rb').read()
    iv = ctx[:16]
    ctx = ctx[16:]
    aes = AES.new(key,AES.MODE_CBC,iv=iv)
    recover = aes.decrypt(ctx)
    return recover

# Database=========================================
url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-ehiok/endpoint/data/v1/action/"
apikey = UnSeal("./Keys/api.key.ctx",key)
headers = {
  'Content-Type': 'application/json',
  'Access-Control-Request-Headers': '*',
  'api-key': apikey,
} 
# =========================================


def GetKey(keyname):
    action = url + "findOne"
    payload = json.dumps({
    "collection": "Keys",
    "database": "CompanyData",
    "dataSource": "CA",
    "filter": {"name":keyname},
    "projection":{
        "value":1
    }
    })
    r = requests.request("POST", action, headers=headers, data=payload)
    return json.loads(r.text)['document']['value']

# def PrivateKeyGen(pk):
#     mk = GetKey("master key")
#     ctx = bytes.fromhex(mk)
#     iv = ctx[:16]
#     ctx = ctx[16:]
#     aes = AES.new(key,AES.MODE_CBC,iv=iv)
#     recover = aes.decrypt(ctx)
#     mk = cpabe.bytesToObject(recover,cpabe.groupObj)
#     cpabe.PrivateKeyGen(pk,mk,attribute=)
def send(message ,client : socket.socket):
    client.send(message.encode())
    return

def UsernameExist(username):
    action = url + "find"
    payload = json.dumps({
        "collection": "Employee Accounts",
        "database": "CompanyData",
        "dataSource": "CA",
        "filter": {"username":username},
        "projection":{
            "username": username
        }
    })
    response = requests.request("POST",action,headers=headers,data=payload)
    usernames =  json.loads(response.text)
    for name in usernames['documents']:
        if name['username'] == username:
            return True
    return False

def register(username,password):

    if(UsernameExist(username) == True):
        return -1
    else:
        action = url + "insertOne"
        payload = json.dumps({
            "collection": "Employee Accounts",
            "database": "CompanyData",
            "dataSource": "CA",
            "document":{
                "username": username,
                "password": password,
                "verified": False
            }

        })
        response = requests.request("POST",action,headers=headers,data=payload)
        if response:
            return True
        else:
            return False

def login(username,password):   
    action = url + "findOne"

    payload = json.dumps({
        "collection": "Employee Accounts",
        "database": "CompanyData",
        "dataSource": "CA",
        "filter" : {"username":username},
        "projection":{
            "password": 1
        }
    })    
    response = requests.request("POST",action,headers=headers,data=payload)
    if response:
        dbpasswd = json.loads(response.text)
        dbpasswd = dbpasswd['document']
        if dbpasswd != None:
            if dbpasswd['password'] == password:
                return 1 
            else:
                return -1
        else:
            return -2
    else:
        return 0

def verify(fullname,dob,cccd):
    action = url + "findOne"
    payload = json.dumps({
        "collection": "Employees",
        "database": "CompanyData",
        "dataSource": "CA",
        "filter" : {"cccd":cccd,"name":fullname,"dob":dob},
        "projection":{
            "name":1,
            "dob":1,
            "cccd":1,
        }
    })    

    response = requests.request("POST", action, headers=headers, data=payload)
    result = json.loads(response.text)['document']
    if result:
        return True
    return False

def isVerified(username):
    action = url + "findOne"
    payload = json.dumps({
        "collection": "Employee Accounts",
        "database": "CompanyData",
        "dataSource": "CA",
        "filter" : {"username":username},
        "projection":{
            "verified":1
        }
    })    
    
    response = requests.request("POST", action, headers=headers, data=payload)
    result = json.loads(response.text)['document']['verified']
    if result:
        return True
    return False    

def updateVerifiedProfile(username,fullname):
    action = url + "updateOne"
    payload = json.dumps({
    "collection": "Employees",
    "database": "CompanyData",
    "dataSource": "CA",
    "filter": {"name":fullname},
    "update":{
        "$set": {
            "registered" : True,
            "username":username
        }
      }
    })
    r = requests.request("POST", action, headers=headers, data=payload)  
    payload = json.dumps({
    "collection": "Employee Accounts",
    "database": "CompanyData",
    "dataSource": "CA",
    "filter": {"username":username},
    "update":{
        "$set": {
            "verified" : True
        }
      }
    })
    r = requests.request("POST", action, headers=headers, data=payload)  
    return

def GetDictValue(param,dict):
    for i in dict:
      for key in i.keys():
         if key == param:
            return i[key]

def handle_message(message : str, client : socket.socket):
    try:
        if(message):
            if(message.startswith('/register')):
                msg = message.split(' ')
                username = msg[1].strip()
                password = msg[2].strip()
                state = register(username,password)
                if state == True :
                    send("Registered! Please login and verify to continue...",client)
                    return f"{username} registered!"
                elif state == -1 :
                    send("Username already existed!",client)
                else:
                    return "An error occured while user register"
            elif(message.startswith('/login')):
                msg = message.split(' ')
                username = msg[1]
                password = msg[2]
                state = login(username,password)
                if(state == 1):
                    send("Loged in.",client)
                    session.append({client:username})
                    return f"{username} loged in."
                elif(state == 0):
                    send("Account not existed",client)
                    return None 
                elif(state == -1):
                    send("Wrong password. Please try again.",client)
                    return None
                elif(state == -2):
                    send("Account not existed",client)
                    return None
                else:
                    return "An error occured while user login"
            elif(message.startswith('/verify')):
                msg = message.split(' ')
                fullname = msg[1]
                dob = msg[2]
                cccd = msg[3]
                username = GetDictValue(param=client,dict=session)
                if(isVerified(username)):
                    send("You already verified!",client)
                    return None 
                else:
                    if verify(fullname,dob,cccd):
                        send("@Verified! Welcome to Secloudity",client)
                        updateVerifiedProfile(username,fullname)
                        return f"{fullname} verified with account {username}."
                    else:
                        send("Information you provided is not correct. Please check again.",client)
                        return None
            elif(message.startswith('/key')):
                pk = GetKey("public key")
                send("@PUBLIC" + pk,client)
                # sk = PrivateKeyGen(pk)
                send("@PRIVATE",client)
                username = GetDictValue(param=client,dict=session)
                return f"Sent keys to {username}"
            else:
                return None
        else:    
            return None
    except Exception as error:
        return error
def handle_client(client : ssl.SSLSocket):
  while True:
      try:
          message = client.read()
          msg = handle_message(message=message.decode(),client=client)

          if(msg):
            print(f"[LOG {datetime.now()}] : {msg}")
      except:
          index = clients.index(client)
          clients.remove(client)
          client.close()
          break

def LISTEN():
    while True:
        client, addr = server.accept()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('../ssl/20.205.46.109.crt','../ssl/20.205.46.109.key')
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        server_ssl = context.wrap_socket(
            client,
            server_side=True
        )
        try:
            client_thr = threading.Thread(target=handle_client,args=[server_ssl])
            client_thr.start()
        except Exception as error:
            print(f"[LOG {datetime.now()}] : ",error)
        # thread = threading.Thread(target=handle_client,args=(server_ssl,client,))
        # thread.start()
        # clients.append(client)

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

    SECLOUDITY CERTIFICATION AUTHORITY
    """
    print(banner)
def main():
    Banner()
    LISTEN()

if __name__ == '__main__':
    main()

