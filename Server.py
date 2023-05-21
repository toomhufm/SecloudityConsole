import socket
import threading
import sqlite3
from MyCrypto import CPABE as cpabe
# Initialize Server Socket
userID = 0
IP = '127.0.0.1'
PORT = 9999
ENDPOINT = (IP,PORT)
clients = []
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ENDPOINT)
server.listen()
# Database Stuff
conn = sqlite3.connect("database.db")
c = conn.cursor()
# =========================================

def handle_message(message : str):
    if(message.startswith("@register")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        c.execute(f"""
          INSERT INTO CUSTOMER VALUES ({userID},{username},{password})
        """)
        conn.commit()
        userID += 1
        return "[+]" + username + "registered!"
    if(message.startswith("@login")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        
    else:
      return message

def handle_client(client):
  while True:
      try:
          message = client.recv(1024)
          msg = handle_message(message=message.decode())
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
    LISTEN()

if __name__ == '__main__':
    main()

