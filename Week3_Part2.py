from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode, base64_decode

# Task 2.1: Signing a file 1.
# Use the signing code from CryptoLab2 Task 3.1 to create a signature for a data file


def hashData(backend, data):
    myhash = hashes.SHA256()
    hasher_sha256 = hashes.Hash(myhash, backend)
    hasher_sha256.update(data)
    digest = hasher_sha256.finalize()

    return myhash, digest


def getMyhashDigest(file_to_sign):
    backend = default_backend()
    with open(file_to_sign, 'rb') as file:
        data_to_encrypt = file.read()

    return hashData(backend, data_to_encrypt)


def sign_file(password, file_to_sign, private_key_file, sig_filename):
    backend = default_backend()

    #with open(file_to_sign, 'rb') as file:
     #   data_to_encrypt = file.read()

    #myhash = hashes.SHA256()
    #hasher_sha256 = hashes.Hash(myhash, backend)
    #hasher_sha256.update(data_to_encrypt)
    #digest = hasher_sha256.finalize()

    myhash, digest = getMyhashDigest(file_to_sign)

    #load the private key from task 2
    password = bytes(password, 'utf-8')

    with open(private_key_file, 'rb') as file:
        private_key = serialization.load_pem_private_key(
            data=file.read(),
            password=password,
            backend=backend)

    # hashed data needs to be padded so it fits correctly
    pad = padding.PKCS1v15()

    sig = base64_encode(
        private_key.sign(
            data=digest,
            padding=pad,
            algorithm=utils.Prehashed(myhash)))[0]

    sig_file = open(sig_filename, "wb")
    sig_file.write(b"-----BEGIN SIGNATURE-----\n")
    sig_file.write(sig)
    sig_file.write(b"-----END SIGNATURE-----\n")
    sig_file.close()


user1_keyfile = "kr_user1.pem"
user1_pubkeyfile = "ku_user1.pem"
user1_signature_file = "encryptme.sig"
user1_certfile = "user1_cert.pem"
file_to_sign = "encryptme.txt"
password = "user 1 password"
sign_file(password, file_to_sign, user1_keyfile, user1_signature_file)


# Task 2.2: Verifying a signature 1. Use the verification code from CryptoLab2 Task 3.2 to verify the signature
def verify_sig(user_certfile, sig_file, file_to_sign):
    backend = default_backend()

    with open(user_certfile, 'rb') as file:
        certificate = x509.load_pem_x509_certificate(
            data=file.read(),
            backend=backend)

    public_key = certificate.public_key()
    # Use the PKCS1v15 padding
    pad = padding.PKCS1v15()

    # Load the signature from the signature file
    with open(sig_file, 'rb') as file:
        # get signature from file
        sig = file.read().split(b"-----BEGIN SIGNATURE-----\n")[1].split(b"\n-----END SIGNATURE-----")[0]
        #print("sig", sig)

        myhash, digest = getMyhashDigest(file_to_sign)

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


verify_sig(user1_certfile, user1_signature_file, file_to_sign)


def verify_certificate(user_certfile):

    backend = default_backend()

    with open(user_certfile, 'rb') as file:
        certificate = x509.load_pem_x509_certificate(
            data=file.read(),
            backend=backend)

    public_key = certificate.public_key()
    sig = certificate.signature
    #print("sig is", sig)
    data = certificate.tbs_certificate_bytes

    myhash, digest = hashData(backend, data)
    pad = padding.PKCS1v15()

    try:
        public_key.verify(
            #signature=base64_decode(sig)[0],
            signature=sig,
            data=digest,
            padding=pad,
            algorithm=utils.Prehashed(myhash))
    except:
        print("sig is invalid")
    else:
        print("sig is valid")


verify_certificate(user1_certfile)
