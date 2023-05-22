import socket
import threading
import sqlite3
import random
import concurrent.futures
from MyCrypto import CPABE as cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT

# Initialize Server Socket
IP = '127.0.0.1'
PORT = 9999
ENDPOINT = (IP,PORT)
clients = []
session = []
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
  c.execute(f"INSERT INTO CUSTOMERS VALUES ({userID},'{password}','{username}')")
  conn.commit()
  conn.close()
  return

def login(username,password):
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
    f"SELECT PASSWORD,CUSTOMERID FROM CUSTOMERS WHERE USERNAME = '{username}'"
  )
  sv_password,id = c.fetchall()[0]
  conn.commit()
  conn.close()
  if(sv_password == password):
     return True,id
  else:
     return False,None

def create_group(ownerid : int,groupname : str,publickey : str,masterkey : str):
  groupID = random.randint(0,100) + 1000
  conn = sqlite3.connect('database.db')
  c = conn.cursor()
  c.execute(
     f"INSERT INTO GROUPS VALUES ({groupID},{ownerid},'{groupname}','{publickey}','{masterkey}')"
  )
  conn.commit()
  conn.close()
  return

def KeyGen():
    groupObj = PairingGroup('SS512')
    (pk,mk) = cpabe.KeyGen(groupObj)
    (pkb,mkb) = cpabe.KeyToBytes(pk,mk,groupObj)
    return pkb.decode(),mkb.decode()

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
        logged,id = login(username,password)
        if(logged):
           session.append({client:id})
           send("Logged in. Welcome to Secloudity.\nPress Enter to continue...",client)
           return f"{username} logged in"
        else:
           send("Wrong password",client)
           return None
    if(message.startswith('@create')):
        msg = message.split(' ')
        groupname = msg[1]
        publickey,masterkey = KeyGen()
        ownerID = 0
        for i in session:
          for key in i.keys():
             if key == client:
                ownerID = i[key]
        send(f"Created group {groupname}",client)
        create_thread = threading.Thread(target=create_group, args=[ownerID,groupname,publickey,masterkey])
        create_thread.start()
        return f"Created group {groupname}"
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

