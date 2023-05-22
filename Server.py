import socket
import threading
import sqlite3
import random
import concurrent.futures
from MyCrypto import CPABE as cpabe
# Initialize Server Socket
IP = '127.0.0.1'
PORT = 9999
ENDPOINT = (IP,PORT)
clients = []
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ENDPOINT)
server.listen()
# Thread

# =========================================

def send(message : str,client : socket.socket):
   client.send(message.encode())

def register(username,password):
  userID = random.randint(0, 100)
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(f"insert into customers values ({userID},'{password}','{username}')")
  conn.commit()
  conn.close()
  return

def login(username,password):
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
    f"select password from CUSTOMERS where username = '{username}'"
  )
  sv_password = c.fetchall()[0][0]
  conn.commit()
  conn.close()
  if(sv_password == password):
     return True
  else:
     return False
def handle_message(message : str, client : socket.socket):
    if(message.startswith("@register")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        send("Registered, please login.\nPress Enter to continue...",client)
        register_thread = threading.Thread(target=register,args=[username,password])
        register_thread.start()
        return "[+] " + username + " registered!"
    if(message.startswith("@login")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged = login(username,password)
        if(logged):
           send("Logged in. Welcome to Secloudity.\nPress Enter to continue...",client)
           return f"{username} logged in"
        else:
           send("Wrong password",client)
           return None

    else:
      return message

def handle_client(client):
  while True:
      try:
          message = client.recv(4096)
          msg = handle_message(message=message.decode(),client=client)
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

