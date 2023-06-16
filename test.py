# import subprocess
# command = 'sudo /bin/bash ./unseal_api.sh'
# apikey = subprocess.check_output(command, shell=True)
# apikey = apikey.decode()
# import requests
# import json
# url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-ehiok/endpoint/data/v1/action/"
# headers = {
#   'Content-Type': 'application/json',
#   'Access-Control-Request-Headers': '*',
#   'api-key': apikey,
# } 
# def UsernameExist(username):
#     action = url + "find"
#     payload = json.dumps({
#         "collection": "Employee Accounts",
#         "database": "CompanyData",
#         "dataSource": "CA",
#         "filter": {"username":username},
#         "projection":{
#             "username": username
#         }
#     })
#     response = requests.request("POST",action,headers=headers,data=payload)
#     usernames =  json.loads(response.text)
#     for name in usernames['documents']:
#         print(name)
#         if name['username'] == username:
#             return True
#     return False

# def register(username,password):

#     if(UsernameExist(username) == True):
#         return -1
#     else:
#         action = url + "insertOne"
#         payload = json.dumps({
#             "collection": "Employee Accounts",
#             "database": "CompanyData",
#             "dataSource": "CA",
#             "document":{
#                 "username": username,
#                 "password": password,
#                 "verified": False
#             }

#         })
#         response = requests.request("POST",action,headers=headers,data=payload)
#         if response:
#             return True
#         else:
#             return False
# print(UsernameExist("test"))

from string import printable
import hashlib
import binascii


def obfucastePassword(password):
  length = len(password)
  res = ""
  for i in range(length):
    res += printable[ord(password[i]) % 94]
  return hashlib.sha256(res.encode()).digest()
  
a = obfucastePassword("anhduc2404")

print((a))