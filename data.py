import sqlite3
import hashlib , binascii
conn = sqlite3.connect('database.db')
a = []
c = conn.cursor()

def GetDictValue(param,dict):
    for i in dict:
      for key in i.keys():
         if i[key] == param:
            return key
id = 87
username = "t00m"
password = "anhduc2404"
salt = password[2:6]
hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())

c.execute(
    f"SELECT USERNAME FROM CUSTOMERS WHERE CUSTOMERID = {id}"
)
data = (c.fetchall()[0][0])
print(data)
# for i in password:
#     a.append({i[0]:i[1]})
# print(a)
conn.commit()
conn.close()

# print(GetDictValue(78,a))