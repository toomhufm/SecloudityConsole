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
# Initialize Server Socket
IP = '0.0.0.0'
PORT = 1337
ENDPOINT = (IP,PORT)
clients = []
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ENDPOINT)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.listen()
# Thread

# =========================================

def send(message ,client : ssl.SSLSocket):
    client.write(message.encode())
    return

def register(username,password):
    return

def login(username,password):   
    return

def GetDictValue(param,dict):
    for i in dict:
      for key in i.keys():
         if key == param:
            return i[key]

def handle_message(message : str, client : ssl.SSLSocket):
    if(message):
        if message.startswith('/regiser'):
            msg = message.split(' ')
            username = msg[1]
            passwd = msg[2]

    else:
        return None

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

                SECLOUDITY
    """
    print(banner)
def main():
    Banner()
    LISTEN()

if __name__ == '__main__':
    main()

