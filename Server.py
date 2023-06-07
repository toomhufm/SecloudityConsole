import socket
import threading
import sqlite3
import random
import base64
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from MyCrypto.curve25519 import *
import os
import binascii
from Crypto.Cipher import AES
import hashlib , pickle
# Initialize Server Socket
IP = '127.0.0.1'
PORT = 9999
ENDPOINT = (IP,PORT)
clients = []
session = []
groups = []
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ENDPOINT)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.listen()
# Thread

# =========================================

def send(message ,client : socket.socket):
   client.send(message.encode())
   return

def register(username,password):
  userID = random.randint(0, 100)
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(f"INSERT INTO CUSTOMERS VALUES ({userID},'{password}','{username}')")
  conn.commit()
  conn.close()
  return

def login(username,password):
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
    f"SELECT PASSWORD,CUSTOMERID FROM CUSTOMERS WHERE USERNAME = '{username}'"
  )
  sv_password,id = c.fetchall()[0]
  conn.commit()
  conn.close()
  if(sv_password == password):
     return True,id
  else:
     return False,None

def AESEncryption(message,key):
    encobj = AES.new(key, AES.MODE_GCM)
    ciphertext,authTag=encobj.encrypt_and_digest(message)
    return(ciphertext,authTag,encobj.nonce)

def AESDecryption(message):
    key = open('app-secret','rb').read().decode()
    message = bytes.fromhex(message)
    authTag = message[:16]
    nonce = message[16:32]
    ciphertext = message[32:]
    encobj = AES.new(bytes.fromhex(key),  AES.MODE_GCM, nonce)
    return(encobj.decrypt_and_verify(ciphertext, authTag))


def create_group(ownerid : int,groupname : str,publickey : str,masterkey : str):
  groupID = random.randint(0,100) + 1000
  key = open('app-secret','rb').read().decode()
  (cipher,authTag,nonce) = AESEncryption(masterkey.encode(),bytes.fromhex(key))
  masterkey = binascii.hexlify(authTag + nonce + cipher).decode()
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
     f"INSERT INTO GROUPS VALUES ({groupID},{ownerid},'{groupname}','{publickey}','{masterkey}')"
  )
  conn.commit()
  c.execute(
     f"INSERT INTO CUSTOMER_GROUP VALUES ({groupID},{ownerid},'Owner','')"
  )
  conn.commit()
  conn.close()
  groups.append({groupID:ownerid})
  return

def accept(memberID,attributes,groupID):
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
     f"INSERT INTO CUSTOMER_GROUP VALUES ({groupID},{memberID},'Member','{attributes}')"
  )
  conn.commit()
  conn.close()
  return 

def KeyGen():
    (pk,mk) = cpabe.KeyGen()
    (pkb,mkb) = cpabe.KeyToBytes(pk,mk)
    return pkb.decode(),mkb.decode()

def GetDictValue(param,dict):
    for i in dict:
      for key in i.keys():
         if key == param:
            return i[key]
def GetUser(id):
   for i in session:
      for key in i.keys():
         if i[key][0] == id:
            return key
def GetUsername(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
       f"SELECT USERNAME FROM CUSTOMERS WHERE CUSTOMERID = {id}"
    )
    username = c.fetchall()[0][0]   
    conn.commit()
    conn.close()
    return username
def GetGroup():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        f"SELECT GroupID,OwnerID FROM GROUPS"
    )
    data = (c.fetchall())
    for i in data:
        groups.append({i[0]:i[1]})
    conn.commit()
    conn.close()
def GetPublicKey(groupID,client : socket.socket):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
       f"SELECT PUBLICKEY FROM GROUPS WHERE GROUPID = {groupID}"
    )
    pk = c.fetchall()[0][0]
    conn.commit()
    conn.close()
    send(pk,client)
    return

def SaveFile(filecontent : bytes,filename,groupID):
    with open(f'./ServerStorage/{groupID}_{filename}','wb') as f:
       f.write(filecontent)
    return

def Download(userID : int,filename : str , groupID : int, client : socket.socket):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
          f"""SELECT ATTRIBUTE FROM CUSTOMER_GROUP CG, CUSTOMERS C 
             WHERE CG.CUSTOMERID = C.CUSTOMERID AND C.CUSTOMERID = {userID} AND GROUPID = {groupID}
          """
    )
    attribute = c.fetchall()[0][0].split(',')
    attribute_list = []
    for attr in attribute:
       attribute_list.append(attr.upper())
    conn.commit()
    c.execute(
       f"SELECT PUBLICKEY,MASTERKEY FROM GROUPS WHERE GROUPID = {groupID}"
    )
    (pk,mk) = c.fetchall()[0]
    conn.commit()
    conn.close()
    groupObj = PairingGroup('SS512')
    pkb = cpabe.bytesToObject(pk.encode(),groupObj)
    decrypted_mk = AESDecryption(mk)
    mkb = cpabe.bytesToObject(decrypted_mk,groupObj)
    user_sk = cpabe.PrivateKeyGen(pkb,mkb,attribute_list)
    encrypted_file_content = f'./ServerStorage/{filename}'
    decryted_file_content = cpabe.ABEdecryption(encrypted_file_content,pkb,user_sk)
    if(decryted_file_content):
        client_pub = bytes.fromhex(GetDictValue(client,session)[1]).decode()
        shared_secret = multscalar(session_secret_key,client_pub)
        aes_key = hashlib.sha256(shared_secret.encode()).digest()
        (ciphertext,authTag,nonce) = AESEncryption(decryted_file_content,aes_key)
        send(f'@download {filename.replace(".scd","")} ' + binascii.hexlify(authTag+nonce+ciphertext).decode(),client)
    else:
       send("Your are not allow to download this file",client)
    return

def Views(userID : int, client : socket.socket):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
      f"""SELECT G.GroupID, G.GroupName , Role FROM CUSTOMER_GROUP CG, CUSTOMERS C , GROUPS G
        WHERE CG.CUSTOMERID = C.CUSTOMERID AND CG.GroupID = G.GroupID AND C.CUSTOMERID = {userID}"""
    )  
    data = c.fetchall()  
    conn.commit()
    conn.close()
    tosend = b"@views " + binascii.hexlify(pickle.dumps(data))
    client.send(tosend)
    return 

def IsUserInGroup(userID : int, groupID : int):
   conn = sqlite3.connect('database.db')
   c = conn.cursor()
   c.execute(
      f"""
      SELECT C.CustomerID FROM CUSTOMER_GROUP CG, CUSTOMERS C WHERE CG.CustomerID = C.CustomerID AND CG.GroupID = {groupID} AND C.CustomerID = {userID} 
      """
   )
   data = c.fetchall()
   conn.commit()
   conn.close()
   if(data):
      return True
   else:
      return False

def handle_message(message : str, client : socket.socket):
    if(message.startswith("@register")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        send("Registered, please login.\nPress Enter to continue...",client)
        register_thread = threading.Thread(target=register,args=[username,password])
        register_thread.start()
        return "[+] " + username + " registered!"
    if(message.startswith("@login")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged,id = login(username,password)
        if(logged):
          #  session.append({client:[id,'']})
          for _client in session:
            for key in _client.keys():
               if key == client:
                  _client[key][0] = id
          send("Logged in. Welcome to Secloudity.\nPress Enter to continue...",client)
          return f"{username} logged in"
        else:
           send("Wrong password",client)
           return None  
    if(message.startswith('@create')):
        msg = message.split(' ')
        groupname = msg[1]
        publickey,masterkey = KeyGen()
        ownerID = int(GetDictValue(client,session)[0])  
        send(f"Created group {groupname}",client)
        create_thread = threading.Thread(target=create_group, args=[ownerID,groupname,publickey,masterkey])
        create_thread.start()
        return f"Created group {groupname}\nPress Enter to continue..."
    if(message.startswith('@join')):
        msg = message.split(' ')
        groupid = msg[1]
        ownerid = GetDictValue(int(groupid),groups)
        owner = GetUser(ownerid)
        userid = int(GetDictValue(client,session)[0])
        username = GetUsername(userid)
        send(f"Group {groupid} join request from {username} #{userid}\n",owner)
        send(f"Use '/accept <userID> <attributes> <groupID>' to add member to group and give attributes\nUse '/reject <userID>' to reject join request",owner)
        return None
    if(message.startswith('@accept')):
        msg = message.split(' ')
        groupID = int(msg[3])
        memberID = int(msg[1])
        attributes = msg[2]
        senderID = int(GetDictValue(client,session)[0])
        ownerID = GetDictValue(groupID,groups)
        member = GetUser(memberID)
        print(senderID == ownerID)
        if(senderID == ownerID):
          accept_thread = threading.Thread(target=accept, args=[memberID,attributes,groupID])
          accept_thread.start()
          send(f"Your request to join group #{groupID} is accepted",member)
        else:
          send("You are not the group owner!",client)
        return None
    if(message.startswith('@reject')):
        msg = message.split(' ')
        receiverID = int(msg[1])
        receiver = GetUser(receiverID)
        send("Your request is rejected!",receiver)
        return None
    if(message.startswith('@pk')):
        msg = message.split(' ')
        groupID = int(msg[1])
        pk_thread = threading.Thread(target=GetPublicKey,args=[groupID,client])
        pk_thread.start()
        return "Sent public key"
    if(message.startswith('QHVwbG9hZCA')):
        msg = base64.b64decode(message).split(b' ')
        # print(msg)
        groupID = msg[1].decode()
        filename = msg[2].decode()
        encrypted = msg[3]
        savefile_thread = threading.Thread(target=SaveFile,args=[encrypted,filename,groupID])
        savefile_thread.start()
        savefile_thread.join()
        send("File uploaded",client)
        return None
    if(message.startswith('@ecdh')):
        pub_key = message.split(' ')[1]
        session.append({client:['',pub_key]})
        send('ecdh ' + binascii.hexlify(session_public_key.encode()).decode(),client)
        return None
    if(message.startswith('@download')):
        msg = message.split(' ')
        groupID = int(msg[1])
        filename = msg[2]
        userID = int(GetDictValue(client,session)[0])
        if IsUserInGroup(userID,groupID):
            down_thread = threading.Thread(target=Download,args=[userID,filename,groupID,client])
            down_thread.start()
            down_thread.join()
        else:
           send("You are not group member!",client)
        return None
    if(message.startswith('@views')):
        userID = int(GetDictValue(client,session)[0])
        view_thread = threading.Thread(target=Views,args=[userID,client])
        view_thread.start()
        view_thread.join()
        return None
    else:
      return message

def handle_client(client):
  while True:
      try:
          message = client.recv(4096)
          msg = handle_message(message=message.decode(),client=client)

          if(msg):
            print(f"[LOG] : {msg}")
      except:
          index = clients.index(client)
          clients.remove(client)
          client.close()
          break

def LISTEN():
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client,args=(client,))
        thread.start()
        clients.append(client)

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
    """
    print(banner)
def main():
    Banner()
    GetGroup()
    LISTEN()

if __name__ == '__main__':
    global session_public_key
    global session_secret_key
    session_secret_key = os.urandom(32)
    session_public_key = base_point_mult(session_secret_key)
    main()

