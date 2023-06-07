import threading
import socket
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
client.connect(('127.0.0.1', 9999))
client.send(b'@ecdh ' + binascii.hexlify(session_public_key.encode()))
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


def AESDecryption(message):
    shared_secret = multscalar(session_secret_key,bytes.fromhex(session_server_public_key).decode())
    key = hashlib.sha256(shared_secret.encode()).digest()
    message = bytes.fromhex(message)
    authTag = message[:16]
    nonce = message[16:32]
    ciphertext = message[32:]
    encobj = AES.new(key,  AES.MODE_GCM, nonce)
    return(encobj.decrypt_and_verify(ciphertext, authTag))

def ViewsData(data):
    to_print = [0]*(len(data)-1)
    files = data[len(data)-1].split('\n')
    for i in range(len(data)-1):
        groupfile = []
        for f in files:
            if f.startswith(str(data[i][0])):
                groupfile.append(f)
            else: 
                continue
        data[i] += ('\n'.join(groupfile),) 
    for i in range(0,len(data)-1):
        to_print[i] = [data[i][0],data[i][1],data[i][2],data[i][3]]
    print(tabulate(to_print,headers=["Group ID","Group Name","Role","Files"],stralign="center",tablefmt="grid"))
    print("Press Enter to continue...")
    return

def client_receive():
    global isAuth
    global receivedpk
    global session_server_public_key
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if(message):
                if(message.startswith('Logged in. Welcome to Secloudity.')):
                    isAuth = True
                    print(f"[NOTI] : {message}")
                elif(message.startswith('eJy')):
                    print("[NOTI] : Received public key for encryption")
                    receivedpk = message.encode()
                elif(message.startswith('@views')):
                    msg = message.split('@views ')[1].encode()
                    data = binascii.unhexlify(msg)
                    data = pickle.loads(binascii.unhexlify(msg))
                    print("[Info] : ")
                    ViewsData(data)
                elif(message.startswith('ecdh')):
                    session_server_public_key = message.split(' ')[1]
                elif(message.startswith('@download')):
                    filename = message.split(' ')[1]
                    encrypt_message = message.split(' ')[2]
                    decrypt_message = AESDecryption(encrypt_message)
                    if(decrypt_message):
                        with open(f"./Downloads/{filename}","wb") as f:
                            f.write(decrypt_message)
                            f.close()
                        print("[NOTI] : Downloaded file")
                    else:
                        print("[NOTI] : Failed to verify file")
                else:
                    print(f"[NOTI] : {message}")
            else:
                pass
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    
def encrypt(message):
    global encrypted
    global encrypted_file_name
    filepath = input("[+] Enter path to file : ")
    policy = input("[+] Please provide policy for encryption : ")
    global receivedpk
    pubkey = cpabe.LoadKey(receivedpk)
    encrypted,encrypted_file_name = cpabe.ABEencryption(filepath,pubkey,policy)
    return 


def handle_input(message : str):
    if(message):
        global encrypted
        global encrypted_file_name
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
            if message.startswith('/upload'):
                msg = message.split(' ')
                groupID = msg[1]
                enc_thread = threading.Thread(target=encrypt,args=[message])
                enc_thread.start()
                enc_thread.join()
                to_send = message.replace('/upload','@upload').encode() + b' ' + encrypted_file_name + b' ' + encrypted
                to_send = base64.b64encode(to_send)
                # print(to_send)
                # client.send(to_send)
                return to_send
            if message.startswith('/download'):
                return message.replace('/download','@download').encode()
            if message.startswith('/views'):
                return message.replace('/views','@views').encode()
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
    global receivedpk
    global isAuth 
    global encrypted 
    global encrypted_file_name
    isAuth = False
    receivedpk = b''
    encrypted = ''
    encrypted_file_name = ''
    Banner()
    main()