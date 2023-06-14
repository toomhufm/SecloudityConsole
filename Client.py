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
    ca_certs='../ssl/rootCA.crt'
    )

client_ssl.write("Hello Server!")
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
    /register <username> <password>   : register
    /login <username> <password>      : login
    /create <group name>              : create group
    /join <group id>                  : join a group
    /key <group id>                   : get group public key for encryption
    /upload <group id>                : upload file to a group
    /download <group id> <file name>  : download file from a group
    /views                            : view all your groups
    ===============================================================
    """
    print(message)

def client_receive():
    while True:
        try:
            message = client.recv(4096*4).decode('utf-8')
            if(message):
                print(message)
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    

def handle_input(message : str):
    return message
def client_send():
    while True:
        message = handle_input(input(">> "))
        if(message):
            client.send(message)
            # print(message)

def main():
    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()
    send_thread = threading.Thread(target=client_send)
    send_thread.start()

if __name__ == '__main__':
    global receivedpk
    global isAuth 
    global encrypted 
    global encrypted_file_name
    isAuth = True
    receivedpk = b''
    encrypted = ''
    encrypted_file_name = ''
    Banner()
    main()