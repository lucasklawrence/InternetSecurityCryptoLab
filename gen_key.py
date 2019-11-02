from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def gen_keys(password, private_key_file, public_key_file):
    backend = default_backend()

    #exponent is public key value
    #key size is number of bits in key
    #use the open ssl backent
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=backend)

    public_key = private_key.public_key()

    password = bytes(password, encoding='utf-8')

    #Encoding is PEM (Privacy Enhanced Mail), base64 encoded DER (Distinguished Encoding Rules) data
    #Format is PKCS#8  - private key serialization format (see RFC5208)
    #Encryption is provided by a built-in algorithm
    pem_kr = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PrivateFormat.PKCS8,
                                       encryption_algorithm=serialization.BestAvailableEncryption(password))

    pem_ku = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)

    kr_file = open(private_key_file, "wb")
    kr_file.write(pem_kr)
    kr_file.close()

    ku_file = open(public_key_file, "wb")
    ku_file.write(pem_ku)
    ku_file.close()

    return private_key, public_key

#gen_keys()