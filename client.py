import socket
import json
import time


cipher_specs = ["RSA_AES"]


def send_receive(message):
    client_socket.send(message.encode())
    print("\nSent:", str(message))
    
    data = client_socket.recv(2048).decode()
    print("Received:", str(data))
    
    return json.loads(data)
# end send_receive


# takes the data from the server as parameter and returns the next message to send
def SSL_HandShake():
    # Hello phase: cipher suites
    h1 = '{"id": "H1", "text": "client hello", "cipher_suites": ["RSA_AES"]}'
    h2 = send_receive(h1)
    
    if h2["id"] != "H2":
        print("Expected H2 header")
        return
    
    chosen_suite = h2["cipher_suite"]
# end SSL_HandShake


# client script:
host = socket.gethostname()  # both apps running on same pc
port = 5000
client_socket = socket.socket()  # create new socket

client_socket.connect((host, port))  # connect to the server
print("Connected to server")

SSL_HandShake()

client_socket.close()  # close the connection

