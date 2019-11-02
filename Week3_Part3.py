from encrypt import encrypt_file, sign_file, verify_sig, verify_certificate, decode_file_final, getUser2PrivateKey
#from Week3_Part2 import sign_file
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
import os

user1_encrypted_private_key_file = "kr_user1.pem"
user2_encrypted_private_key_file = "kr_user2.pem"
user1_public_key = "ku_user1.pem"
user2_public_key = "ku_user2.pem"
user1_certificate = "user1_cert.pem"
user2_certificate = "user2_cert.pem"

class Keystore:
    def __init__(self, private_key_file, user1_cert, user2_cert):
        self.private_key_file = private_key_file
        self.user1_cert = user1_cert
        self.user2_cert = user2_cert

###########################################
# So k1 has
# i. User 1 encrypted private key file
# ii. User 1 certificate
# iii. User 2 certificate

# And k2 has
# i. User 2 encrypted private key file
# ii. User 2 certificate
# iii. User 1 certificate


k1 = Keystore(user1_encrypted_private_key_file, user1_certificate, user2_certificate)
k2 = Keystore(user2_encrypted_private_key_file, user1_certificate, user2_certificate)
###########################################


# Now as user 1:
#   a.Create an encrypted file with a randomly generated secret key
# i.Symmetric encryption, AES-128

file_to_encrypt = "encryptme.txt"
encrypted_file = "encrypted.txt"
encrypted_file_key = "encrypted.key"
encrypted_file_iv = "encrypted.iv"

signature_file = "encrypted.sig"

#encrypts encryptme.txt to encrypted.txt using a random key
original_random_key = os.urandom(16)
encrypt_file(original_random_key, encrypted_file_key, encrypted_file_iv, file_to_encrypt, encrypted_file)

# encrypts key_file
key_file = "encrypted.key"
encrypted_key_file = "encrypted_key.txt"

backend = default_backend()
with open(k1.user2_cert, 'rb') as file:
    certificate = x509.load_pem_x509_certificate(
        data=file.read(),
        backend=backend)

    user2_public_key = certificate.public_key()
    pad = asympadding.PKCS1v15()
    key_encrypted = user2_public_key.encrypt(original_random_key, padding=pad)
    with open(encrypted_key_file, 'wb') as file2:
        file2.write(key_encrypted)

# Create a message digest of the encrypted file and the encrypted key
# Sign thismessage digest with user 1’s private key
signature_file = "encrypted.sig"
key_signature_file = "encrypted_key.sig"
sign_file("user 1 password", encrypted_file, k1.private_key_file, signature_file)
sign_file("user 1 password", encrypted_key_file, k1.private_key_file, key_signature_file)

# Copy all files to user 2 and as user 2:
#Verify the signature using user 1’s public key
#  i. From User 1 certificate in keystore k2
verify_sig(k2.user1_cert, signature_file, encrypted_file)
verify_sig(k2.user1_cert, key_signature_file, encrypted_key_file)
verify_certificate(user1_certificate)

#  b. Decrypt the secret key using user 2’s private key
# i. From User 2 private key file in keystore k2

user2_priv_key = getUser2PrivateKey(k2.private_key_file, b"user 2 secret")
pad = asympadding.PKCS1v15()
with open(encrypted_key_file, 'rb') as file:
    encrypted_keyy = file.read()
    secret_key = user2_priv_key.decrypt(encrypted_keyy, padding=pad)

#decrypt encrypted file using secret key
decode_file_final(secret_key, encrypted_file, encrypted_file_iv, "decrypted.txt")

