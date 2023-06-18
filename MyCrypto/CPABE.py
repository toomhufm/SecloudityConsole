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
1. Random abe_key 
2. Encrypt abe_key with CP-ABE , this produced abe_key_ctxt 
3. Serialize abe_key_ctxt then attach to the output file
4. Pack the length of serialized abe_key_ctxt and write to the first 8 bytes of output
6. Random IV (16 bytes) then write to the output file
7. Hash the abe_key to make aes_key
8. Encrypt the file with AES256-CFB then write the encrypted data to the output 
===============================================================================================
Output file structure : [8][16][abe_key][encrypted_data]
===============================================================================================
Decryption : 
1. Extract the abe_key_size , IV 
2. Recover abe_key_ctxt_b = ciphertext[24:abe_key_len+24] 
3. Deserialized abe_key_ctxt_b then decrypt it
4. If policy satisfied to decrypt the abe_key_ctxt_b, we hash the abe_key to retrive the 
aes_key
5. Decrypt the file with aes_key
===============================================================================================


"""

groupObj = PairingGroup('SS512')
cpabe = AC17CPABE(groupObj,2)

def ABEencryption(filename,pk,policy):
    msg = open(filename,"rb").read()
    """
    Create Session key then encrypt with CP-ABE 
    Encode Session key and attach to file
    """

    serialize_encoder = ac17.mySerializeAPI()


    abe_key = groupObj.random(GT)
    abe_key_ctxt = cpabe.encrypt(pk,abe_key,policy)


    abe_key_ctxt_b = serialize_encoder.jsonify_ctxt(abe_key_ctxt)
    abe_key_ctxt_b = base64.b64encode(abe_key_ctxt_b.encode())
    abe_key_size = len(abe_key_ctxt_b)
    stream = struct.pack('Q',abe_key_size)
    namesplit = filename.split('/')
    outname = f"{namesplit[len(namesplit)-1]}.scd"

    """
    Use AES to encrypt the file then attach needed component
    """

    aes_key = hashlib.sha256(str(abe_key).encode()).digest()
    iv = os.urandom(16)

    encryptor = AES.new(aes_key,AES.MODE_GCM)
    encrypted_data,authTag = encryptor.encrypt_and_digest(msg)
    nonce = encryptor.nonce
    output = stream + authTag + nonce + abe_key_ctxt_b + encrypted_data

    return output


def ABEdecryption(filecontent,pk,sk):
    serialize_encoder = ac17.mySerializeAPI()
    ciphertext_stream = bytes.fromhex(filecontent)
    abe_key_size = struct.unpack('Q',ciphertext_stream[:8])[0]
    ciphertext = bytes.fromhex(filecontent)
    autTag = ciphertext[8:24]
    nonce = ciphertext[24:40]
    abe_key_ctxt_b = ciphertext[40:abe_key_size+40]
    abe_key_ctxt_b = base64.b64decode(abe_key_ctxt_b)
    abe_key_ctxt = serialize_encoder.unjsonify_ctxt(abe_key_ctxt_b)
    abe_key = cpabe.decrypt(pk,abe_key_ctxt,sk)
    if(abe_key):
        aes_key = hashlib.sha256(str(abe_key).encode()).digest()
        decryptor = AES.new(aes_key,AES.MODE_GCM,nonce)
        decrypted_data = decryptor.decrypt_and_verify(ciphertext[40+abe_key_size:],autTag)
        return decrypted_data
    else:
        return None

def LoadKey(key):
    key = bytesToObject(key,groupObj)
    return key

def KeyToBytes(pk,mk):
    pkb = objectToBytes(pk,groupObj)
    mkb = objectToBytes(mk,groupObj)
    return pkb,mkb

def KeyGen():
    (pk,mk) = cpabe.setup()
    return pk,mk

def PrivateKeyGen(pk,mk,attribute):
    sk = cpabe.keygen(pk,mk,attribute)
    return sk 


