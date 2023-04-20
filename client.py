import socket
import json
import time
import base64

from Crypto.Random import get_random_bytes

from pub_RSA import KE_RSA
from pub_ECC import KE_ECC
import sym_AES


cipher_specs = ["ECC_AES", "RSA_AES"]
sym_alg = None


def send_receive(message):
    client_socket.send(message.encode())
    print("\nSent:", str(message))
    
    data = client_socket.recv(2048).decode()
    print("Received:", str(data))
    
    return json.loads(data)
# end send_receive


def encode64(byte_string):
    return base64.b64encode( byte_string ).decode("UTF-8")
# end encode64()

def decode64(string):
    return base64.b64decode( string.encode("UTF-8") )
# end decode64()


###################################################################################################


def RSA_keyExchange():
    print("\nRSA Key Exchange:")
    
    # C -> S: Kc
    rsa_c = KE_RSA()
    Kc = rsa_c.getPublicKey()
    rsa1_c = '{"id": "RSA1_C", "Kc": "' + encode64(Kc) + '"}'
    
    # S -> C: {Kcs} Ks
    rsa1_s = send_receive(rsa1_c)
    Kcs = rsa_c.decrypt( decode64(rsa1_s["Kcs"]) )  # get sym key
    
    print("\nreceived sym key:", Kcs)
    return Kcs
# end RSA_keyExchange()



def ECC_keyExchange():
    print("\nECC Key Exchange:")
    
    # C -> S: Kc
    ecc_c = KE_ECC()
    Kc = ecc_c.getPublicKey()  # type(): byte string
    ecc1_c = '{"id": "ECC1_C", "Kc": "' + encode64(Kc) + '"}'
    
    # S -> C: {Kcs} Ks
    ecc1_s = send_receive(ecc1_c)
    Kcs = ecc_c.decrypt( decode64(ecc1_s["Kcs"]) )  # get sym key
    
    print("\nreceived sym key:", Kcs)
    return Kcs
# end ECC_keyExchange()


###################################################################################################


def SSL_HandShake():
    # Hello phase: cipher suites
    h_c = '{"id": "H_C", "text": "client hello", "cipher_suites": ["ECC_AES", "RSA_AES"]}'
    h_s = send_receive(h_c)
    
    if h_s["id"] != "H_S":
        print("Expected H_S header")
        return
    
    chosen_suite = h_s["cipher_suite"]
    if chosen_suite == "RSA_AES":
        sym_alg = "AES"
        sym_key = RSA_keyExchange()

    elif chosen_suite == "ECC_AES":
        sym_alg = "AES"
        sym_key = ECC_keyExchange()
    
# end SSL_HandShake



# client script:
host = socket.gethostname()  # both apps running on same pc
port = 5000
client_socket = socket.socket()  # create new socket

client_socket.connect((host, port))  # connect to the server
print("Connected to server")

SSL_HandShake()

client_socket.close()  # close the connection

