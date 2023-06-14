import socket
import ssl
import threading
import random
import base64
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from MyCrypto.curve25519 import *
import os
import binascii
from Crypto.Cipher import AES
import hashlib
from datetime import date
# Initialize Server Socket
IP = '127.0.0.1'
PORT = 1337
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
    return

def login(username,password):   
    return

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

def handle_message(message : str, client : socket.socket):
    return

def handle_client(client):
  while True:
      try:
          message = client.recv(4096)
          msg = handle_message(message=message.decode(),client=client)

          if(msg):
            print(f"[LOG {date.today()}] : {msg}")
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
    LISTEN()

if __name__ == '__main__':
    main()

