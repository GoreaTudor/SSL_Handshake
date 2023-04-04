import socket
import json
import time


cipher_specs = ["RSA_AES"]


def receive():
    data = conn.recv(2048).decode()
    print("\nReceived:", str(data))
    
    if not data:
        conn.close()
        quit()
    
    return json.loads(data)
# end receive

def send(message):
    conn.send(message.encode())
    print("Sent:", str(message))
# end send


def SSL_HandShake():
    while True:
        h1 = receive()
        
        if h1["id"] != "H1":
            print("Expected H2 header")
            return
        
        chosen_suite = 'RSA_AES'
        h2 = '{"id": "H2", "text": "server hello", "cipher_suite": "' + chosen_suite + '"}'
        send(h2)
# end SSL_HandShake


# server script:
host = socket.gethostname()  # both apps running on same pc
port = 5000
server_socket = socket.socket()  # create new socket
server_socket.bind((host, port))  # binds host address and port together

server_socket.listen(1)  # config how many clients the server can listen to
print("Server started")

conn, adr = server_socket.accept()  # accept new connection to client
print("Connection accepted, address is:", str(adr))

SSL_HandShake()

conn.close()

