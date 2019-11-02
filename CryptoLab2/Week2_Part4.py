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

#define blocksize
blocksize = 16

#create backend
backend = default_backend()

#get salt
salt = os.urandom(16)

#create kdf
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=blocksize,
        salt=salt,
        iterations=100000,
        backend=backend)

#create idf
idf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

encrypt_me = "encryptme.txt"
output_file_encrypt = "encrypted.txt"
output_file_decrypt = "decrypted.txt"
output_key_file = "encrypted.key"
output_iv_file = "encrypted.iv"

key = kdf.derive(bytes("key password", encoding='utf-8'))
iv = idf.derive(bytes("iv password", encoding='utf-8'))
key_file = open(output_key_file, "wb")
key_file.write(key)
key_file.close()

iv_file = open(output_iv_file, "wb")
iv_file.write(iv)
iv_file.close()


###############################################
# ENCRYPT FILE
def encrypt_file(backend_encrypt, file_to_encrypt_name, encrypted_file_name):
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.OFB(iv),
        backend=backend_encrypt)

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
            print("Encrypted file: ", file_to_encrypt_name)
            print("Encrypted to: ", encrypted_file_name)
            break
###############################################


encrypt_file(backend, encrypt_me, output_file_encrypt)

###############################################
# Sign encrypted file
def sign_file(file_name, backend_sign):
    with open(file_name, 'rb') as file:
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
            backend=backend_sign)

    # hashed data needs to be padded so it fits correctly
    pad = asympadding.PSS(
                        mgf=asympadding.MGF1(hashes.SHA256()),
                        salt_length=asympadding.PSS.MAX_LENGTH)

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

    print("Signed file with private key and wrote to file.sig")
###############################################


sign_file(output_file_encrypt, backend)

###############################################
# Verify Signature
def verify_signature(filename, backend_sig):
    with open(filename, 'rb') as file:
        data_to_encrypt = file.read()

    myhash = hashes.SHA256()
    hasher_sha256 = hashes.Hash(myhash, backend_sig)
    hasher_sha256.update(data_to_encrypt)
    digest = hasher_sha256.finalize()

    #load the public key from task 2
    with open("ku.pem", 'rb') as file:
        public_key = serialization.load_pem_public_key(
                        data=file.read(),
                        backend=backend_sig)

    # Load the signature from the signature file
    with open("file.sig", 'rb') as file:
        #get signature from file
        sig = file.read().split(b"-----BEGIN SIGNATURE-----\n")[1].split(b"\n-----END SIGNATURE-----")[0]

    # unpad using same algorithm
    pad = asympadding.PSS(
                    mgf=asympadding.MGF1(hashes.SHA256()),
                    salt_length=asympadding.PSS.MAX_LENGTH)

    try:
        public_key.verify(
                        signature=base64_decode(sig)[0],
                        data=digest,
                        padding=pad,
                        algorithm=utils.Prehashed(myhash))
    except:
        print("sig is invalid")
    else:
        print("signature was verified")
###############################################


verify_signature(output_file_encrypt, backend)

################################################
# decode file


def decode_file(input_filename, output_filename, backend_decode):

    prefix_input_file = input_filename.split('.')[0]
    # output_file_key = output_file_name.split('.')
    output_key_file = prefix_input_file + ".key"
    key_file = open(output_key_file, "rb")

    key_decode = bytearray(blocksize)
    key_file.readinto(key_decode)

    output_file_iv = output_filename.split('.')
    output_iv_file = prefix_input_file + ".iv"

    iv_file = open(output_iv_file, "rb")
    iv_decode = bytearray(blocksize)
    iv_file.readinto(iv_decode)

    input_file = open(input_filename, "rb")
    output_file = open(output_filename, "wb")

    # create a mutable array to hold the bytes
    data = bytearray(blocksize)
    totalsize = 0

    cipher = Cipher(
                algorithm=algorithms.AES(key),
                mode=modes.OFB(iv),
                backend=backend_decode)

    decryptor = cipher.decryptor()

    while True:
        # read block from source file
        num = input_file.readinto(data)
        # adjust totalsize
        totalsize += num
        # check if full block read
        if num == blocksize:
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
                print("decrypted file is in decrypted.txt")
                break
            output_file.write(plaintext)


decode_file(output_file_encrypt, output_file_decrypt, backend)