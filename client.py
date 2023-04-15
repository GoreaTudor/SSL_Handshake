import socket
import json
import time

from Crypto.Random import get_random_bytes

from pub_RSA import KE_RSA
import sym_AES


cipher_specs = ["DH_AES", "RSA_AES"]
sym_alg = None


def send_receive(message):
    client_socket.send(message.encode())
    print("\nSent:", str(message))
    
    data = client_socket.recv(2048).decode()
    print("Received:", str(data))
    
    return json.loads(data)
# end send_receive


def RSA_keyExchange():
    # C -> S: Kc
    rsa_c = KE_RSA()
    rsa1_c = '{"id": "RSA1_C", "Kc": "' + str(rsa_c.getPublicKey()) + '"}'
    
    # S -> C: {Kcs} Ks
    rsa1_s = send_receive(rsa1_c)
    Kcs = rsa_c.decrypt(rsa1_s["Kcs"].encode("UTF-8"))  # get sym key
    
    print("received sym key:", Kcs)
    return Kcs
# end RSA_keyExchange()


def DH_keyExchange():
    pass



def SSL_HandShake():
    # Hello phase: cipher suites
    h_c = '{"id": "H_C", "text": "client hello", "cipher_suites": ["DH_AES", "RSA_AES"]}'
    h_s = send_receive(h_c)
    
    if h_s["id"] != "H_S":
        print("Expected H_S header")
        return
    
    chosen_suite = h_s["cipher_suite"]
    if chosen_suite == "DH_AES":
        sym_alg = "AES"
        sym_key = DH_keyExchange()
        
    elif chosen_suite == "RSA_AES":
        sym_alg = "AES"
        sym_key = RSA_keyExchange()
    
# end SSL_HandShake



# client script:
host = socket.gethostname()  # both apps running on same pc
port = 5000
client_socket = socket.socket()  # create new socket

client_socket.connect((host, port))  # connect to the server
print("Connected to server")

SSL_HandShake()

client_socket.close()  # close the connection

