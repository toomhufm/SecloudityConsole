import sqlite3
import hashlib , binascii
conn = sqlite3.connect('database.db')

c = conn.cursor()

username = "t00m"
password = "anhduc2404"
salt = password[2:6]
hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())

c.execute(
    f"select password from CUSTOMERS where username = '{username}'"
)
print(c.fetchall()[0][0])
conn.commit()
conn.close()

