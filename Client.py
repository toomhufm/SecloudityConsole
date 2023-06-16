import threading
import socket,ssl
import hashlib , binascii, base64
import sys, os , pickle
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from Crypto.Cipher import AES
from MyCrypto.curve25519 import *
from tabulate import tabulate
global session_public_key
global session_secret_key
global session_server_public_key
session_secret_key = os.urandom(32)
session_public_key = base_point_mult(session_secret_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('20.205.46.109', 1337))
server_ip = '20.205.46.109'

client_ssl = ssl.wrap_socket(
    client, 
    ca_certs='../ssl/20.205.46.109.crt',
    )

client_ssl.write(b"Hello Server!")
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

def client_receive():
    while True:
        try:
            message = client_ssl.read()
            if(message):
                print(message)
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    

def handle_input(message : str):
    if(message):
        if message.startswith('/help'):
            Help() 
            return None
        if message.startswith('/register') or message.startswith('/login'):
            return None
        if message.startswith('/create'):
            return None
        if message.startswith('/join'):
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
    main()
