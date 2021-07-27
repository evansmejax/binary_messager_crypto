# binary_messager_crypto
End to End Message Encryption with CBC, RSA &amp; AES encryption technology

## Introduction
Nowadays creating secure communication channels is becoming a hot topic . Although this solution may not be optimal, some attempt has been 
made to adopt new latest security and cryptographic standards. While the solution is not ground breaking, a few concepts such a cipher block chaining , 
RSA encryption and challage response protocals have been applied. Encryption is a process in cryptography of encoding messages in ways that makes it 
difficult to understand the message by unmauthorised third parties. Even before the invention of the computers encryption has always been the backbone 
of secure communication.


- Alice creates  a n  bit random number Ra(serial_a) and share  Ra together with the signature of Ra with Bob.
- Bob creates a n  bit random number Rb(serial_b) and share Ra together with the signature of Ra with Alice.
- Bob verifies Ra with its signature. Then Bob generates a n bit random number Rb(serial_b) and sends back to Alice Ra and Rb and their signature.
- Alice confirms if Ra*=Ra and signature match  then the server identity is verified and continues by sending back Rb to the sever with it’s signature. If signatures don’t match Alice drops the connection, notifiying that it might be a man in the middle attack.
- Bob confirms client identity if Rb*=Rb and signature match if so the mutual authentication process is successfully. If signatures don’t match Bob drops the connection, notifiying that it might be a man in the middle attack.
- The Challenge response  is accepted and both parties can now communicate.
- Bob generates a symmetric session key and sends it to Alice. All new communications between Alice and Bob will now be encrypted with symmetric cryptography using AES module.
