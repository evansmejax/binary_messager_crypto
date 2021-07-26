from digest import make_hash_sha512
import os
import socket
import time
from aes import aes_encrypter
import rsa
from cryptography.utils import int_from_bytes
import sys
from base64 import b64decode, b64encode



def size_bin_int(input):
    return int(input, 2)


def size_in_8bit(input):
    return '{0:08b}'.format(input)



def size_in_32bit(input):
    return '{0:032b}'.format(input)

def message_preparer(aes_generated_key, message):
    message = message.rstrip('\n')
    hash_value = make_hash_sha512(aes_generated_key)
    message_length = size_in_32bit(len(message))
    return hash_value + message_length + message


def response_challenge(s, private_client_key, public_client_key, public_server_key):
  
    # work on authentication & create session key
    # Step 1
    # Serial key is sent to server and encrypted with public key

    sequence_id = 1  # holds the sequence numbers in packet's

    serial = int_from_bytes(os.urandom(4), byteorder="big")
    m = size_in_8bit(sequence_id) + size_in_32bit(serial)
    signature_serial = rsa.sign_data(m, private_client_key)
    msg1 = signature_serial + m
    cipher1 = rsa.rsa_cbc_encrypt(msg1, public_server_key)
    s.sendall(cipher1)

    # This delays for one second when under attack
    time.sleep(1)

    # Step 2
    # The Data is Received
    cipher2 = s.recv(size)
    #  Data Decryption
    msg2 = rsa.rsa_cbc_decrypt(cipher2, private_client_key)
    # Data Verification
    signature_serial_server = msg2[:256]
    rsa.verify_data(msg2[256:], signature_serial_server, public_server_key)
    # Data Extraction
    sequence_for_server = msg2[256:256 + 8]
    reply = msg2[256 + 8:256 + 8 + 32]
    server_serial = msg2[256 + 8 + 32:256 + 8 + 32 + 32]

    if reply != size_in_32bit(serial):
        print("There is a signature mismatch")
        return False
    print("Matches")
    print("The Server is now authenticated successfully")

    # update sequence id
    sequence_id = sequence_id + size_bin_int(sequence_for_server)

    m = size_in_8bit(sequence_id) + server_serial
    signature_serial = rsa.sign_data(m, private_client_key)
    msg3 = signature_serial + m
    cipher3 = rsa.rsa_cbc_encrypt(msg3, public_server_key)
    s.sendall(cipher3)
    time.sleep(1)

    print("Challenge Response was Successful")

    # Step 4 save AES session key sent from server
    server_session_key = s.recv(size)
    server_session_key = b64decode(server_session_key)

    decrypted_data = rsa.rsa_cbc_decrypt(server_session_key, private_client_key)
    aes_sig = decrypted_data[:256]
    aes_generated_key = decrypted_data[256:]

    rsa.verify_data(aes_generated_key, aes_sig, public_server_key)
    return aes_generated_key


# confiquration to server
host_server =('localhost')
port = 50000
size = 4096 

print("Trying to connect to server on %s:%d ->" % (host_server, port))
socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_instance.connect((host_server, port))
print("Ok")

print "Loading rsa keys...",
public_server_key = rsa.public_key_loader("rsa_keys/server_pub.pem")
private_client_key = rsa.private_key_loader("rsa_keys/client_pri.pem")
public_client_key = rsa.public_key_loader("rsa_keys/client_pub.pem")
print "Ok"

running_status = 1

print("Challenge Response with server in progress...wait")

aes_generated_key = response_challenge(s, private_client_key, public_client_key, public_server_key)

if aes_generated_key == False:
    socket_instance.close()
    running_status = 0
    print("Server response is wrong")
    print("Disconnecting now")

print("\nAES encryption key is %s\n" % b64encode(aes_generated_key))

while running_status:
    print "Enter new message to send (Press enter to quit) #: ",
    line = sys.stdin.readline()
    if line == '\n':
        running_status = 0
        message = message_preparer(aes_generated_key, "secure-close")
        encrypted_cipher = aes_encrypter(aes_generated_key, message)
        socket_instance.send(encrypted_cipher)
        time.sleep(1)
        print("Client good bye")
        break
    print("Sending the message to server")
    message = message_preparer(aes_generated_key, line)
    encrypted_cipher = aes_encrypter(aes_generated_key, message)
    socket_instance.send(encrypted_cipher)
socket_instance.close()
