import socket
import json
import time

import pub_RSA
import sym_AES


cipher_specs = ["DH_AES", "RSA_AES"]


def send_receive(message):
    client_socket.send(message.encode())
    print("\nSent:", str(message))
    
    data = client_socket.recv(2048).decode()
    print("Received:", str(data))
    
    return json.loads(data)
# end send_receive


def RSA_keyExchange():
    pass


def DH_keyExchange():
    pass


ke_alg = None
sym_alg = None
def SSL_HandShake():
    # Hello phase: cipher suites
    h_c = '{"id": "H_C", "text": "client hello", "cipher_suites": ["DH_AES", "RSA_AES"]}'
    h_s = send_receive(h_c)
    
    if h_s["id"] != "H_S":
        print("Expected H_S header")
        return
    
    chosen_suite = h2["cipher_suite"]
    if chosen_suite == "DH_AES":
        ke_alg = DH_keyExchange()
        sym_alg = "AES"
    elif chosen_suite == "RSA_AES":
        
    ;
# end SSL_HandShake


# client script:
host = socket.gethostname()  # both apps running on same pc
port = 5000
client_socket = socket.socket()  # create new socket

client_socket.connect((host, port))  # connect to the server
print("Connected to server")

SSL_HandShake()

client_socket.close()  # close the connection

