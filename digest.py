import hashlib

# check sum with a SHA-512 hash 
def make_hash_sha512(msg):
    # create instance of sha512 
    sha512 = hashlib.sha512()
    # update hash
    sha512.update(msg)
    # return hash value in hexx
    return sha512.hexdigest()

#  The hash values are compared
def compare(hash1, h2):
    if hash1 != hash2:
        False
    else:
        True
