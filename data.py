# import sqlite3    
# from tabulate import tabulate

# userID = 87
# conn = sqlite3.connect('database.db')
# c = conn.cursor()
# c.execute(
#   f"""SELECT G.GroupID, G.GroupName , Role FROM CUSTOMER_GROUP CG, CUSTOMERS C , GROUPS G
#     WHERE CG.CUSTOMERID = C.CUSTOMERID AND CG.GroupID = G.GroupID AND C.CUSTOMERID = {userID}"""
# )  
# data = c.fetchall()  
# conn.commit()
# conn.close()

# to_print = [0]*len(data)

# for i in range(0,len(data)):
#     to_print[i] = [data[i][0],data[i][1],data[i][2]]
# print(tabulate(to_print,headers=["Group ID","Group Name","Role"]))

# print(type('a'))

import os 
import binascii
with open('app-secret','wb') as f:
    f.write(binascii.hexlify(os.urandom(32)))
    f.close()