import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

blocksize = 16

backend = default_backend()
salt = os.urandom(16)
print("salt", salt.hex())

kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=blocksize,
        salt=salt,
        iterations=100000,
        backend=backend)

idf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

passwd = b'password'
ivval = b'hello'

key = kdf.derive(passwd)
iv = idf.derive(ivval)

print("key", key.hex())
print("iv", iv.hex())

#####
# 2.2
#####
cipher = Cipher(
 algorithm=algorithms.AES(key),
 #mode=modes.CBC(iv),
 mode=modes.ECB(),
 backend=backend)
encryptor = cipher.encryptor()

#mydata = b'this is my long data for this task to ensure that multiple blocks are processed during the cipher'
#print("my data", mydata)
#print("my data hex", mydata.hex())

padder = padding.PKCS7(128).padder()
mydata = b'1234567812345678'
mydata_pad = padder.update(mydata) + padder.finalize()
print("padded data", mydata_pad.hex())
ciphertext = encryptor.update(mydata_pad) + encryptor.finalize()
#ciphertext = encryptor.update(mydata) + encryptor.finalize()
print("ciphertext", ciphertext.hex())

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
print("plaintext", plaintext.hex())