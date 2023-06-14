from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from MyCrypto import CPABE as cpabe
import binascii

from Crypto.Cipher import AES 
from Crypto.Util import Padding
import os

aeskey = bytes.fromhex(open("app-secret",'r').read())
print(len(aeskey))
iv = os.urandom(16)
aes = AES.new(key=aeskey,iv=iv,mode=AES.MODE_CBC)

(pk,mk) = cpabe.KeyGen()

pkb = cpabe.objectToBytes(pk,cpabe.groupObj)
mkb = cpabe.objectToBytes(mk,cpabe.groupObj)
enc_mk = aes.encrypt(Padding.pad(mkb,AES.block_size))

aes2 = AES.new(key=aeskey,iv=iv,mode=AES.MODE_CBC)

dec_mk = aes2.decrypt(enc_mk)

print("IV : ", binascii.hexlify(iv))
print("Public Key : ", binascii.hexlify(pkb))
print("Master Key : ", binascii.hexlify(enc_mk))
# print(Padding.unpad(dec_mk,AES.block_size))

# import requests
# import json
# url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-ehiok/endpoint/data/v1/action/find"
# payload = json.dumps({
#     "collection": "Employees",
#     "database": "CompanyData",
#     "dataSource": "CA",
#     "projection": {
#         "_id": 1,
#         "name": 1,
#         "cccd": 1
#     }
# })

# apikey = open("api.key",'r').read()

# headers = {
#   'Content-Type': 'application/json',
#   'Access-Control-Request-Headers': '*',
#   'api-key': apikey
# }
# response = requests.request("POST", url, headers=headers, data=payload)

# res = json.loads(response.text)
# print(res['documents'][0]['cccd'])