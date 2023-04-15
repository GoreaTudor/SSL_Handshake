import socket
import json
import time

from Crypto.Random import get_random_bytes

from pub_RSA import KE_RSA
import sym_AES


cipher_specs = ["RSA_AES", "DH_AES"]
sym_alg = None


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



def RSA_keyExchange():
    rsa_s = KE_RSA()
    
    # C -> S: Kc
    rsa1_c = receive()
    Kc = rsa1_c["Kc"].encode("UTF-8")
    
    # S -> C: {Kcs} Ks
    Kcs = get_random_bytes(16)
    rsa1_s = '{"id": "RSA1_S", "Kcs": "' + rsa_s.encrypt(Kcs, Kc) + '"}'
    
    print("sent sym key:", Kcs)
    return Kcs
# end RSA_key_Exchange()

def DH_keyExchange():
    pass



sym_alg = None
def SSL_HandShake():
    while True:
        h1 = receive()
        
        if h1["id"] != "H_C":
            print("Expected H_C header")
            return
        
        chosen_suite = "RSA_AES"  # alg for choosing suite req
        
        h2 = '{"id": "H_S", "text": "server hello", "cipher_suite": "' + chosen_suite + '"}'
        send(h2)
        
        if chosen_suite == "DH_AES":
            sym_alg = "AES"
            sym_key = DH_keyExchange()
        
        elif chosen_suite == "RSA_AES":
            sym_alg = "AES"
            sym_key = RSA_keyExchange()
        
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

