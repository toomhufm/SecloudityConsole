# import sqlite3
# import hashlib , binascii
# conn = sqlite3.connect('database.db')

# c = conn.cursor()

# username = "t00m"
# password = "anhduc2404"
# salt = password[2:6]
# hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())

# c.execute(
#     f"select password,customerid from CUSTOMERS where username = '{username}'"
# )
# password , id = (c.fetchall()[0])
# print(password,id)
# conn.commit()
# conn.close()

data = [{'a':'b'},{'c':'d'}]

for i in data:
    for key in i.keys():
        print(key)