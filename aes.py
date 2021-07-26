
from Crypto.Cipher import AES
from Crypto import Random


def aes_key_dumper(aes_key, key_destination_file='aes.key'):
    # the key will be written to a fill
    # it will be overwritted next time

    with open(key_destination_file, 'wb') as out_file:
        out_file.write(aes_key)

# generatate an aes key of n bits
def aes_key_maker(size_in_bits=256):
    s = size_in_bits/8
    new_key = Random.get_random_bytes(s)
    return new_key


#  padding scheme(pkcs5) is applied to input
def pad_pkcs5(x):
    return x + (AES.block_size - len(x) % AES.block_size) * chr(AES.block_size - len(x) % AES.block_size)


# function to padding process
def unpad_pkcs5(x):
    return x[0:-ord(x[-1])]


def aes_encrypter(aes_key, msg):
    message_length = len(msg)
    if message_length % AES.block_size != 0:
        msg = pad_pkcs5(msg)

    # instantiate AES object
    aes_inst = AES.new(aes_key, AES.MODE_ECB)

    # encrypt data
    cipher = aes_inst.encrypt(msg)

    return cipher


# convert encrypted file to a plain text
def aes_decrypter(aes_key, encrypted_data):
    # instantiate AES object to use in decrytion
    aes_inst = AES.new(aes_key, AES.MODE_ECB)  # decrypt  the cipher text as if there is no tomorrow
    plain_txt = aes_inst.decrypt(encrypted_data)

    # unpad plain text before returning
    return unpad_pkcs5(plain_txt)
