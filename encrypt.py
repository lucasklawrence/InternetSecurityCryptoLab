import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode, base64_decode
from cryptography import x509


encrypt_me = "encryptme.txt"
output_file_encrypt = "encrypted.txt"
output_file_decrypt = "decrypted.txt"
#output_key_file = "encrypted.key"
#output_iv_file = "encrypted.iv"


def encrypt_file(key_password, output_key_file, output_iv_file, file_to_encrypt_name, encrypted_file_name):
    backend = default_backend()

    blocksize = 16
    backend = default_backend()
    # get salt
    salt = os.urandom(16)

    # create kdf
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=blocksize,
        salt=salt,
        iterations=100000,
        backend=backend)

    # create idf
    idf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=backend)

    iv = idf.derive(bytes("iv password", encoding='utf-8'))
    key_file = open(output_key_file, "wb")
    key_file.write(key_password)
    key_file.close()

    iv_file = open(output_iv_file, "wb")
    iv_file.write(iv)
    iv_file.close()

    cipher = Cipher(
        algorithm=algorithms.AES(key_password),
        mode=modes.OFB(iv),
        backend=backend)

    encryptor = cipher.encryptor()

    input_file = open(file_to_encrypt_name, "rb")
    output_file = open(encrypted_file_name, "wb")

    data = bytearray(blocksize)
    totalsize = 0
    while True:
        # read block from source file
        num = input_file.readinto(data)
        # adjust totalsize
        totalsize += num

        # check if full block read
        if num == blocksize:
            ciphertext = encryptor.update(bytes(data))
            # write full block to destination
            output_file.write(ciphertext)
        else:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(bytes(data[0:num])) + padder.finalize()
            ciphertext = encryptor.update(bytes(padded_data)) + encryptor.finalize()

            # write subarray to destination and break loop
            output_file.write(ciphertext)
            break


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
    myhash, digest = getMyhashDigest(file_to_sign)

    #load the private key from task 2
    password = bytes(password, 'utf-8')

    with open(private_key_file, 'rb') as file:
        private_key = serialization.load_pem_private_key(
            data=file.read(),
            password=password,
            backend=backend)

    # hashed data needs to be padded so it fits correctly
    pad = asympadding.PKCS1v15()

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

def verify_sig(user_certfile, sig_file, file_to_sign):
    backend = default_backend()

    with open(user_certfile, 'rb') as file:
        certificate = x509.load_pem_x509_certificate(
            data=file.read(),
            backend=backend)

    public_key = certificate.public_key()
    # Use the PKCS1v15 padding
    pad = asympadding.PKCS1v15()

    # Load the signature from the signature file
    with open(sig_file, 'rb') as file:
        # get signature from file
        sig = file.read().split(b"-----BEGIN SIGNATURE-----\n")[1].split(b"\n-----END SIGNATURE-----")[0]

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
    pad = asympadding.PKCS1v15()

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

def decode_file_final(password, input_file, input_file_iv, output_file ):
    backend = default_backend()

    iv_file = open(input_file_iv, "rb")
    iv = iv_file.read()

    input_file = open(input_file, "rb")
    output_file = open(output_file, "wb")

    # create a mutable array to hold the bytes
    data = bytearray(16)
    totalsize = 0

    cipher = Cipher(
        algorithm=algorithms.AES(password),
        mode=modes.OFB(iv),
        backend=backend)

    decryptor = cipher.decryptor()

    while True:
        # read block from source file
        num = input_file.readinto(data)
        # adjust totalsize
        totalsize += num
        # check if full block read
        if num == 16:
            plaintext = decryptor.update(bytes(data))
            last_bytes = plaintext.hex()[-2:]
            num_padding_bytes = int(last_bytes, 16)

            # make sure block is padded correctly when we depad
            valid = 0
            if num_padding_bytes <= 16:
                valid = 1
                left = -4
                for i in range(num_padding_bytes - 1):
                    if num_padding_bytes != int(plaintext.hex()[left:left + 2], 16):
                        valid = 0
                    left = left - 2
            if valid:
                unpadder = padding.PKCS7(128).unpadder()
                unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
                plaintext = decryptor.finalize()
                output_file.write(unpadded_data)
                break
            output_file.write(plaintext)

def getUser2PrivateKey(key_file, password):
    backend = default_backend()
    with open(key_file, "rb") as file:
        private_key = serialization.load_pem_private_key(
            data=file.read(),
            password=password,
            backend=backend)

    return private_key
