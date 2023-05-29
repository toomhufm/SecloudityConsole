import threading
import socket
import hashlib , binascii, base64
import sys, os
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
import asyncio
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
    /key <group id>                   : get group public key for encryption
    /upload <group id>                : upload file to a group
    /download <group id> <file name>  : download file from a group
    /views                            : view all your groups
    ===============================================================
    """
    print(message)

def client_receive():
    global isAuth
    global receivedpk
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if(message):
                if(message.startswith('Logged in. Welcome to Secloudity.')):
                    isAuth = True
                    print(f"[NOTI] : {message}")
                elif(message.startswith('eJyd')):
                    print("[NOTI] : Received public key for encryption")
                    receivedpk = message.encode()
                else:
                    print(f"[NOTI] : {message}")
            else:
                pass
        except:
            print('Error!')
            client.close()
            break

async def send(client,message : bytes):
    await client.send(message)

async def upload_file(client,message):
    msg = message.split(' ')
    groupID = msg[1]
    encrypted, filename = encrypt()
    to_send = message.replace('/upload','@upload').encode() + b' ' + filename + b' ' + encrypted
    await send(client,to_send)

def encrypt():
    filepath = input("[+] Enter path to file : ")
    policy = input("[+] Please provide policy for encryption : ")
    global receivedpk
    groupObj = PairingGroup('SS512')
    pubkey = cpabe.LoadKey(receivedpk,groupObj)
    encrypted,filename = cpabe.ABEencryption(filepath,pubkey,policy,groupObj)
    return encrypted,filename

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
            if message.startswith('/reject'):
                to_send = message.replace('/reject','@reject')
                return to_send.encode()   
            if message.startswith('/key'):
                to_send = message.replace('/key','@pk')
                return to_send.encode()

        else:
            print("[!] You must login first")     
        return message.encode()
    else:
        return None
async def client_send(client,message):
    client.send(message)
            # print(message)

def main():
    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()
    loop = asyncio.get_event_loop()
    while True:
        message = input(">> ")
        if message == "exit":
            break
        elif message.startswith("/upload"):
            loop.run_until_complete(upload_file(client, message))
        else:
            msg = handle_input(message)
            if(msg):
                loop.run_until_complete(client_send(client, msg))
            else:
                continue

if __name__ == '__main__':
    global receivedpk
    global isAuth 
    isAuth = False
    receivedpk = b''
    Banner()
    main()