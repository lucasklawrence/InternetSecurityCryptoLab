from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode, base64_decode

# Load and hash the data to be signed, from Task 1

backend = default_backend()

# load and hash the data to be signed from task 1
#SHA 256
with open("encryptme.txt", 'rb') as file:
    data_to_encrypt = file.read()


myhash = hashes.SHA256()
hasher_sha256 = hashes.Hash(myhash, backend)
hasher_sha256.update(data_to_encrypt)
digest = hasher_sha256.finalize()

#load the public key from task 2
with open("ku.pem", 'rb') as file:
    public_key = serialization.load_pem_public_key(
                    data=file.read(),
                    backend=backend)

# Load the signature from the signature file
with open("file.sig", 'rb') as file:
    #get signature from file
    sig = file.read().split(b"-----BEGIN SIGNATURE-----\n")[1].split(b"\n-----END SIGNATURE-----")[0]
    print("sig", sig)

# unpad using same algorithm
# unpad using same algorithm
    pad = padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH)

    try:
        public_key.verify(
                        signature=base64_decode(sig)[0],
                        data=digest,
                        padding=pad,
                        algorithm=utils.Prehashed(myhash))
    except:
        print("sig is invalid")
    else:
        print("sig is valid")