from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import padding
import random
from Crypto.Util import strxor

import warnings

b = 128

BLOCK_SIZE = b


def pad_rsa(x):
    return x + (BLOCK_SIZE - len(x) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(x) % BLOCK_SIZE)


def unpad_rsa(x):
    return x[0:-ord(x[-1])]


def msg_db(msg, description, curr_mode):
    # show debug log msg
    print("- "+description+" = length " + str(len(msg)))
    print("\t----")
    if curr_mode == "hex":
        print("\t: %s" % hexlify(msg))
    else:
        print("\t: " + msg)
    print("\t----\n")


def generate_private_key(bit_size=2048):
    # return private rsa key with a size of 2048 bit by default
    new_private_key = rsa.generate_private_key(
            p_exponent=(65537 * 1),
            rsa_key_size=bit_size,
            default_backend=default_backend()
    )
    return new_private_key


def private_key_loader(path):
     # It returns public key from the file in pem 
    with open(path, "rb") as k:
        loaded_private_key = serialization.load_pem_private_key(
                k.read(),
                password=None,
                backend=default_backend()
        )

        return loaded_private_key


def public_key_loader(path):
    # It returns public key from the file in pem 
    with open(path, "rb") as k:
        loaded_public_key = serialization.load_pem_public_key(
                k.read(),
                backend=default_backend()
        )

        return loaded_public_key


def private_key_serializer(priv_key):
    # performs serialization on the private key
    pem_file = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )

    return pem_file


def public_key_serializer(priv_key):
    # performs serialization on the public key
    pub_key = priv_key.public_key()
    pem_file = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_file


def save_data_to_file(d, fileData):
    with open(fileData, "wb") as file:
        file.write(d)
        file.close()


def sign_data(msg, priv_key):
    signer = priv_key.signer(
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),  # change to sha 512 in the future
                    salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
    
    signer.update(msg)
    signature = signer.finalize()

    return signature


def public_key(priv_key):
    return priv_key.public_key()


def verify_data(msg, signature, pub_key): 
    verifier = pub_key.verifier(
            signature,
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
    verifier.update(msg)

    verifier.verify()


def rsa_encrypt(msg, pub_key):
    # The message is encrypted using rsa padding
    cipher = pub_key.encrypt(
            msg,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
            )
    )

    return cipher


# cipher gets decrypted 
def rsa_decrypt(text, priv_key):
    p_text = priv_key.decrypt(text,
                                    padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                    )
                                    )
    return p_text



def rsa_cbc_encrypt(d, key):
    # cbc with rsa is applied
    # pad data to rsa chunks  128 bits
    padded_data = pad_rsa(d)

 
    splitted_input = []
    for x in range(0, len(padded_data)):
        p_d = padded_data[x:x + BLOCK_SIZE]
        splitted_input.append(p_d)

    ciphers_array = []

    # IV vector made ready encryption 1 
    # Random bytes 128 bits is created
    from random import randbytes
    IV = randbytes(128)
    IV2 = IV

    for data in splitted_input:
        data_to_xor = strxor.strxor(data, IV)
        # scramble
        encrypted_cipher = rsa_encrypt(data_to_xor, key)

        IV = encrypted_cipher[0:128]
        ciphers_array.append(encrypted_cipher)
    # append the final block 
    ciphers_array.append(IV2)

    return "".join(ciphers_array)


def rsa_cbc_decrypt(d, rsa_key):
    # separate iv from text
    IV = d[-128:]
    encrypted_text = d[:-128]

    # split cipher text in chunks  of 2*RSA Block size
    ciphers_array = []
    for y in range(0, len(encrypted_text), 2 * BLOCK_SIZE):
        chunk = encrypted_text[y:y + 2 * BLOCK_SIZE]
        ciphers_array.append(chunk)

    # decrypt each chunk
    decrypted_text = []
    for c in ciphers_array:
        data_to_xor = rsa_decrypt(c, rsa_key)

        clear_text = strxor.strxor(data_to_xor, IV)
        IV = c[0:128]
        decrypted_text.append(clear_text)

    str_data = "".join(decrypted_text)
    result = unpad_rsa(str_data)
    return result



