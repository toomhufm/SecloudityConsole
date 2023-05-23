import threading
import socket
import hashlib , binascii, base64
import sys, os
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from Crypto.Cipher import AES
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 9999))
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
    /upload <group id> <path to file> : upload file to a group
    /download <group id> <file name>  : download file from a group
    /views                            : view all your groups
    ===============================================================
    """
    print(message)

def client_receive():
    global isAuth
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if(message):
                if(message.startswith('Logged in. Welcome to Secloudity.')):
                    isAuth = True
                    print(f"[NOTI] : {message}")
                else:
                    print(f"[NOTI] : {message}")
            else:
                pass
        except:
            print('Error!')
            client.close()
            break

def handle_input(message : str):
    if(message):
        if message.startswith('/help'):
            Help() 
            return None
        if message.startswith('/register') or message.startswith('/login'):
            msg = message.split(' ')
            prefix = msg[0]
            username = msg[1]
            password = msg[2]
            salt = password[2:6]
            hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())
            if(prefix == '/register'):
                to_send = f"@register {username} {hashed.decode()}"
            else:
                to_send = f"@login {username} {hashed.decode()}"
            return to_send.encode()
        if(isAuth):
            if message.startswith('/create'):
                msg = message.split(' ')
                groupname = msg[1]
                to_send = f"@create {groupname}"
                return to_send.encode()
            if message.startswith('/join'):
                msg = message.split(' ')
                groupid = msg[1]
                to_send = f"@join {groupid}"
                return to_send.encode()
            if message.startswith('/accept'):
                to_send = message.replace('/accept','@accept')
                return to_send.encode()          
        else:
            print("[!] You must login first")     
        return message.encode()
    else:
        return None
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
    global isAuth 
    isAuth = False
    Banner()
    main()