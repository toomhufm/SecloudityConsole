from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from . import AC17Serialize as ac17
from Crypto.Util.number import bytes_to_long,long_to_bytes
from Crypto.Cipher import AES 
import hashlib , base64, zlib, json
import binascii
import os
import pickle
import struct
"""
===============================================================================================
Encryption : 
1. Random session_key 
2. Encrypt session_key with CP-ABE , this produced session_key_ctxt 
3. Serialize session_key_ctxt then attach to the output file
4. Pack the length of serialized session_key_ctxt and write to the first 8 bytes of output
6. Random IV (16 bytes) then write to the output file
7. Hash the session_key to make aes_key
8. Encrypt the file with AES256-CFB then write the encrypted data to the output 
===============================================================================================
Output file structure : [8][16][session_key][encrypted_data]
===============================================================================================
Decryption : 
1. Extract the session_key_size , IV 
2. Recover session_key_ctxt_b = ciphertext[24:session_key_len+24] 
3. Deserialized session_key_ctxt_b then decrypt it
4. If policy satisfied to decrypt the session_key_ctxt_b, we hash the session_key to retrive the 
aes_key
5. Decrypt the file with aes_key
===============================================================================================


"""



def ABEencryption(filename,pk,policy,group):
    cpabe = AC17CPABE(group,2)
    msg = open(filename,"rb").read()
    """
    Create Session key then encrypt with CP-ABE 
    Encode Session key and attach to file
    """

    serialize_encoder = ac17.mySerializeAPI()


    session_key = group.random(GT)
    session_key_ctxt = cpabe.encrypt(pk,session_key,policy)

    # for i in session_key_ctxt.values(): print((i))

    session_key_ctxt_b = serialize_encoder.jsonify_ctxt(session_key_ctxt)
    session_key_ctxt_b = base64.b64encode(session_key_ctxt_b.encode())
    session_key_size = len(session_key_ctxt_b)
    # print("Session Key " , (session_key_ctxt_b))
    # print(f" Session key size : {session_key_size}")
    output = open(f"{filename}.scd","wb")
    stream = struct.pack('Q',session_key_size)
    output.write(stream)


    """
    Use AES-GCM to encrypt the file then attach needed component
    """

    aes_key = hashlib.sha256(str(session_key).encode()).digest()
    iv = os.urandom(16)

    # print(f"Key : {aes_key}")
    # print(f"IV : {iv}")
    encryptor = AES.new(aes_key,AES.MODE_CFB,iv)
    encrypted_data = encryptor.encrypt(msg)
    # print(f"Encrypted : {encrypted_data} ")
    # print("Session Key Length : ",len(session_key_ctxt_b))
    # output = open("encrypted.scd","wb")
    output.write(iv)
    output.write(session_key_ctxt_b)
    output.write(encrypted_data)
    output.close()


def ABEdecryption(filename,pk,policy,sk,group):
    serialize_encoder = ac17.mySerializeAPI()
    ciphertext_stream = open(filename,"rb")
    cpabe = AC17CPABE(group,2)
    session_key_size = struct.unpack('Q',ciphertext_stream.read(struct.calcsize('Q')))[0]
    ciphertext_stream.close()
    ciphertext = open(filename,"rb").read()
    # print(f" Session key size : {session_key_size}")
    iv = ciphertext[8:24]
    # print(f"IV : {iv}")
    session_key_ctxt_b = ciphertext[24:session_key_size+24]
    session_key_ctxt_b = base64.b64decode(session_key_ctxt_b)
    # print("Session Key B64 : ",session_key_ctxt_b)
    session_key_ctxt = serialize_encoder.unjsonify_ctxt(session_key_ctxt_b)
    session_key = cpabe.decrypt(pk,session_key_ctxt,sk)
    # bytesToObject(session_key_ctxt_b,group)
    # print(session_key)  
    if(session_key):
        aes_key = hashlib.sha256(str(session_key).encode()).digest()
        encryptor = AES.new(aes_key,AES.MODE_CFB,iv)
        decrypted_data = encryptor.decrypt(ciphertext[8+16+session_key_size:])
        with open("a.docx","wb") as f :
            f.write(decrypted_data)
    else:
        print("Policy not satisfied!")

    # session_key = cpabe.decrypt()

def LoadKey(path_to_pk,path_to_sk,group):
    pk = bytesToObject(open(path_to_pk,"rb").read(),group)
    sk = bytesToObject(open(path_to_sk,"rb").read(),group)
    return pk,sk

# def SaveKey(path_to_pk,pk,path_to_sk,sk,group):
#     with open(path_to_pk,"wb") as f:
#         f.write(objectToBytes(pk,group))
#     with open(path_to_sk,"wb") as f:
#         f.write(objectToBytes(sk,group))

def KeyToBytes(pk,mk,group):
    pkb = objectToBytes(pk,group)
    mkb = objectToBytes(mk,group)
    return pkb,mkb

def KeyGen(group):
    cpabe = AC17CPABE(group,2)
    (pk,mk) = cpabe.setup()
    return pk,mk

def PrivateKeyGen(pk,mk,attribute):
    sk = cpabe.keygen(pk,mk,attribute)
    return sk 


if __name__ == "__main__":
    debug = True
#     # instantiate a bilinear pairing map
    pairing_group = PairingGroup('SS512')

#     # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group,2)

#     atrribute = ["ONE","TWO","THREE"]
#     atrribute2 = ["FOUR","FIVE"]
#     policy_string = '((ONE and THREE) and (TWO OR FOUR))'

    # (pk,mk) = cpabe.setup()
    # sk = cpabe.keygen(pk,mk,atrribute)

    # SaveKey('public_key',pk,'secret_key',sk,pairing_group)

    # filename = "BaoCao.docx"
    # Load the PK and SK

    # (lpk,lsk) = LoadKey('public_key2','secret_key2',pairing_group)

    # print(lpk)
    # print(lsk)


    # cipher = encryption(filename,lpk,policy_string,pairing_group)
    # filename = "encrypted.scd"

    # recover = decryption(filename,lpk,policy_string,lsk,pairing_group)
    # res = cpabe.decrypt(pk,cipher,sk)
    # print(res)
