# Documentation for Project 3

## Overview of Application
This application illustrates secure communication and connection between client and VPN server using a Transport Layer Security (TLS) handshake. The TLS handshake is computed through encryption techniques such as certificate verification, asymmetric and symmetric cryptography communication using the cryptgraphy_simulator.py file. Through a series of connections with the secure client, secure server, VPN and certificate authority, we simulate confidentiality and security of transferred data packets through implementation of the TLS handshake. We demonstrate the application of the TLS handshake in the following sections. 
## Format of unsigned certificate
We present the generic structure of an unsigned certificate:

`D_(client_id, pnum)[ip_address, port, (public_key_component, pnum)]`

The variables are defined as such:
* D: This string value indicates what is being presented is a certificate
* client_id (int): A unique identifier for the client
* pnum (int): A prime number is assigned to the public key and attached within parenthesis 
* ip_address (str): Communication with client is done through this IP address
* port (int): Communication with client is done through this port address

## Example Output
Below is an example of user input for communicating with a string message defined with a precursor labeling convention of --message as indicate in the terminal input.

```
(base) garf-4:csc-249-p3-secure-RPC hannahsun$ python3 secure_client.py --message to be or not to be is the question
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (24189, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
Requesting TLS handshake from the server
Receiving signed certificate: D_(32344, 56533)[127.0.0.1,65432,(53739, 56533)]
TLS handshake complete: sent symmetric key '33385', waiting for acknowledgement
Received acknowledgement 'Symmetric key '33385' received', preparing to send message
Sending message 'HMAC_89484[symmetric_33385[to be or not to be is the question]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_89484[symmetric_33385[to be or not to be is the question]]'' [63 bytes]
Decoded message 'to be or not to be is the question' from server
client is done!
```

## Walkthrough of TLS handshake
In order to establish communication with the different components of the TLS handshake, the user first must initialize the VPN, secure server and certificate authority files. The client then sends a request to the VPN server which will begin the secure connection through a TLS handshake. Next, the server will generate a ceritificate using the certificate authority private key. This certificate is called the signed certificate which is then sent back to the client. This signed certificate is verified using the certificate authority public key. If the certificate is not verified, then connection with the server is ended. After the signed certificate has been verified, the client will create a symmetric key. This symmetric key is then encrypted with the public key. The server then decrypts the symmetric key using the private key. Subsequently, messages are encrypted using the symmetric key and HMACs.

## Description of Potential Failures
Based on existing research of Python's eval() function, there are potential vulnerabilities within this functionality that permits execution of malicious code while parsing through a certificate. These command injection attacks are similar to SQL injection attacks. One example of this includes `_import_('os').system('rm-rf/')` which deletes the all of the user's files and directories.

Another security risk in this TLS handshake simulation is the implementation of prime numbers as the asymmetric key generation scheme. Smaller prime numbers tend to be more vulnerable since malicious actors can factor numbers in order to obtain the private key. Using fixed prime numbers generates keys with predictable patterns which then can be exploited through reverse-engineering. 

## Acknowledgements
https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20Injection
https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1
https://semgrep.dev/docs/cheat-sheets/python-code-injection
https://www.stackhawk.com/blog/command-injection-python/
https://www.techtarget.com/searchsecurity/definition/asymmetric-cryptography#:~:text=In%20asymmetric%20encryption%2C%20there%20must,an%20equivalent%20level%20of%20security.
