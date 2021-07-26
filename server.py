import time
import select
from Crypto import Random
from rsa import public_key_loader, private_key_loader
from digest import make_hash_sha512
from cryptography.utils import int_from_bytes
import os
import socket
import sys
from base64 import b64encode
import threading
import rsa
import aes


class Server:
    def __init__(self):
        self.port = 50000
        self.host_server = ''
        self.threads_array = []
        self.backlog = 5
        self.server = None
        self.size = 4096
        print("Server is loading the rsa keys...\n")
        self.public_key = public_key_loader("rsa_keys/server_pub.pem")
        self.private_key = private_key_loader("rsa_keys/server_pri.pem")
        print("loading ..ok\n")

    def open_socket(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host_server, self.port))
            self.server.listen(5)
        except socket.error, (value, message):
            if self.server:
                self.server.close()
            print "Could not open socket: " + message
            sys.exit(1)

    def run(self):
        print "Starting the Server...\n",
        self.open_socket()
        print "server is now opened..ok\n"
        input = [self.server, sys.stdin]
        running = 1
        print("The Server runs on port "), self.port
        print("\nWaiting for a new connection...\n")
        while running:
            inputready, outputready, exceptready = select.select(input, [], [])

            for s in inputready:

                if s == self.server:
                    # server socket handling
                    c = Client(self.server.accept())
                    c.start()
                    self.threads_array.append(c)

                elif s == sys.stdin:
                    # standard input handling
                    junk = sys.stdin.readline()
                    running = 0

        # end all threads_array

        self.server.close()
        for c in self.threads_array:
            c.join()


class Client(threading.Thread):
    def __init__(self, (client, address)):
        threading.Thread.__init__(self)
        self.client = client
        self.address = address
        self.size = 4096
        self.client_public_key = public_key_loader("rsa_keys/client_pub.pem")
        self.server_private_key = private_key_loader("rsa_keys/server_pri.pem")


    def size_in_32bit(self, n):
        return '{0:032b}'.format(n)

    def size_in_8bit(self, n):
        return '{0:08b}'.format(n)

    def size_bin_int(self, n):
        return int(n, 2)

    def prepare_message(self, plain_text):
        h = plain_text[0:128]
        n = plain_text[128:128 + 32]
        msg_len = self.size_bin_int(n)
        text = plain_text[128 + 32:]
        return text, h, msg_len

    def message_checksum(self, message, msg_hash):
        h = make_hash_sha512(message)
        if h == msg_hash:
            return True

    def log(self, id, message=[]):
        with open("connection.log", 'ab') as logfile:
            logfile.write("-- msg --\n")
            logfile.write("client: " + str(self.address) + "\n")
            logfile.write("message_id: " + str(id) + "\n")
            logfile.write("message: " + message[0] + "\n")
            logfile.write("msg_len: " + str(message[1]) + "\n")
            logfile.write("sha512: " + message[2] + "\n")
            logfile.write("-- end --\n")

    def run(self):
        print "Client Handler tid: %s" % self.getName()
        running = 1

        message_id = 0
        sequence_id = 1
        print "Challenging of Response in progress...wait\n",
        # Step 1: Magic Number is Accepted
        cipher1 = self.client.recv(self.size)
        # Decryption begins
        msg1 = rsa.rsa_cbc_decrypt(cipher1, self.server_private_key)
        #  authenticity Verification
        serial_client_signature = msg1[:256]
        rsa.verify_data(msg1[256:], serial_client_signature, self.client_public_key)

        #  Data is Extract
        sequence_id_client = msg1[256:256 + 8]
        serial_client = msg1[256 + 8:]

        # Step 2: 
        serial = int_from_bytes(os.urandom(4), byteorder="big")

        # sequence is updated
        sequence_id = sequence_id + self.size_bin_int(sequence_id_client)
        data = self.size_in_8bit(sequence_id) + serial_client + self.size_in_32bit(serial)
        signature2 = rsa.sign_data(data, self.server_private_key)
        msg2 = signature2 + data
        cipher2 = rsa.rsa_cbc_encrypt(msg2, self.client_public_key)
        self.client.send(cipher2)
        time.sleep(1)

        # Step 3
        cipher3 = self.client.recv(self.size)
        msg3 = rsa.rsa_cbc_decrypt(cipher3, self.server_private_key)
        signature3 = msg3[:256]
        rsa.verify_data(msg3[256:], signature3, self.client_public_key)

        # Session Key
        #  sequence id  is updated
        sequence_id = sequence_id + self.size_bin_int(msg3[256:256 + 8])
        serial_client_reply = msg3[256 + 8:256 + 8 + 32]
        if serial_client_reply == self.size_in_32bit(serial):
            print("User Has been Authenticated Successfuly!\n")
            print("Sending the Session Key to the server...")
            aes_key = Random.get_random_bytes(32)
            aes_key_sig = rsa.sign_data(aes_key, self.server_private_key)
            key = aes_key_sig + aes_key
            encrypted_aes_key = rsa.rsa_cbc_encrypt(key, self.client_public_key)
            self.client.send(b64encode(encrypted_aes_key))
            print("ok")
        else:
            print("Can't authenticate user or man in the middle attack")
            print("Terminating Connection now")
            self.client.close()
            running = 0

        while running:
            aes_cipher_text = self.client.recv(self.size)


            plain_text = aes.aes_decrypter(aes_key, aes_cipher_text)

            text, msg_hash, msg_len = self.prepare_message(plain_text)
            message_id += 1

            self.log(message_id, [text, msg_len, msg_hash])
            print "\n* New Message Received from: ",
            print self.address
            print "\tMessage Content: %s" % text
            print "Comparing Message Checksum: %s" % text
            if self.message_checksum(aes_key, msg_hash):
                print "\tHash check ok"
            else:
                print "\tHash values don't match damaged message! "
            if text == "secure-close":
                print "\tClient Has been disconected Gracefully"
                self.client.close()
                running = 0


if __name__ == "__main__":
    s = Server()
    s.run()
