from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

backend = default_backend()

#SHA 256


user_input = input("Enter some data: ")
user_byte_array = bytes(user_input, 'utf-8')

myhash_sha256 = hashes.SHA256()
hasher_sha256 = hashes.Hash(myhash_sha256, backend)
hasher_sha256.update(user_byte_array)
digest_sha256 = hasher_sha256.finalize()

myhash_md5 = hashes.MD5()
hasher_md5 = hashes.Hash(myhash_md5, backend)
hasher_md5.update(user_byte_array)
digest_md5 = hasher_md5.finalize()

myhash_md5 = hashes.MD5()
hasher_md5 = hashes.Hash(myhash_md5, backend)
hasher_md5.update(user_byte_array)
digest_md5 = hasher_md5.finalize()

myhash_sha1 = hashes.SHA1()
hasher_sha1 = hashes.Hash(myhash_sha1, backend)
hasher_sha1.update(user_byte_array)
digest_sha1 = hasher_sha1.finalize()

myhash_sha384 = hashes.SHA384()
hasher_sha384 = hashes.Hash(myhash_sha384, backend)
hasher_sha384.update(user_byte_array)
digest_sha384 = hasher_sha384.finalize()

myhash_sha512 = hashes.SHA512()
hasher_sha512 = hashes.Hash(myhash_sha512, backend)
hasher_sha512.update(user_byte_array)
digest_sha512 = hasher_sha512.finalize()



print("user byte array", user_byte_array)
print("digest md5", digest_md5)
print("digest SHA 1", digest_sha1)
print("digest SHA 256", digest_sha256)
print("digest SHA 384", digest_sha384)
print("digest SHA 512", digest_sha512)


