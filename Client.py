import threading
import socket
import hashlib , binascii, base64


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
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            print(message)
        except:
            print('Error!')
            client.close()
            break

def handle_input(message : str):
    if message.startswith('/help'):
        Help() 
        return None
    if message.startswith('/register'):
        msg = message.split(' ')
        username = msg[1]
        password = hashlib.sha256(msg[2].encode()).digest()
        salt = bytes(base64.b64encode(password[2:8]))
        to_send = f"@register {username} {binascii.hexlify(password+salt).decode()}"
        return to_send
    if message.startswith('/login'):
        msg = message.split(' ')
        username = msg[1]
        password = hashlib.sha256(msg[2].encode()).digest()
        salt = bytes(base64.b64encode(password[2:8]))
        to_send = f"@login {username} {binascii.hexlify(password+salt).decode()}"
        return to_send
def client_send():
    while True:
        message = handle_input(input(">> "))
        if(message):
            client.send(message.encode('utf-8'))

def main():
    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()

    send_thread = threading.Thread(target=client_send)
    send_thread.start()

if __name__ == '__main__':
    Banner()
    main()