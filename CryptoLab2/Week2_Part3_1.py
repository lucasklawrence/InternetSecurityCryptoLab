from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode

backend = default_backend()

# load and hash the data to be signed from task 1
#SHA 256
with open("encryptme.txt", 'rb') as file:
    data_to_encrypt = file.read()

myhash = hashes.SHA256()
hasher_sha256 = hashes.Hash(myhash, backend)
hasher_sha256.update(data_to_encrypt)
digest = hasher_sha256.finalize()

#load the private key from task 2
password = bytes("hello", 'utf-8')

with open("kr.pem", 'rb') as file:
    private_key = serialization.load_pem_private_key(
        data=file.read(),
        password=password,
        backend=backend)

# hashed data needs to be padded so it fits correctly
pad = padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH)

sig = base64_encode(
    private_key.sign(
        data=digest,
        padding=pad,
        algorithm=utils.Prehashed(myhash)))[0]

sig_file = open("file.sig", "wb")
sig_file.write(b"-----BEGIN SIGNATURE-----\n")
sig_file.write(sig)
sig_file.write(b"-----END SIGNATURE-----\n")
sig_file.close()




