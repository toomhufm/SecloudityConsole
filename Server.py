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
from datetime import date
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

def send(message ,client : socket.socket):
    client.send(message.encode())
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

def handle_message(message : str, client : socket.socket):
    return

def handle_client(client):
  while True:
      try:
          message = server.ssl.read()
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
        server_ssl = ssl.wrap_socket(
            client,
            server_side=True,
            certfile='../ssl/rootCA.crt',
            keyfile='../ssl/rootCA.key',
            ssl_version=ssl.PROTOCOL_TLSv1
        )
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

