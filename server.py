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


def encode64(byte_string):
    return base64.b64encode( byte_string ).decode("UTF-8")
# end encode64()

def decode64(string):
    return base64.b64decode( string.encode("UTF-8") )
# end decode64()


###################################################################################################


def RSA_keyExchange():
    print("\nRSA Key Exchange:")
    
    rsa_s = KE_RSA()
    
    # C -> S: Kc
    rsa1_c = receive()
    Kc = decode64(rsa1_c["Kc"])
    
    # S -> C: {Kcs} Ks
    Kcs = get_random_bytes(16)
    rsa1_s = '{"id": "RSA1_S", "Kcs": "' + encode64( rsa_s.encrypt(Kcs, Kc) ) + '"}'
    send(rsa1_s)
    
    return Kcs
# end RSA_key_Exchange()



def ECC_keyExchange():
    print("\nECC Key Exchange:")
    
    ecc_s = KE_ECC()
    
    # C -> S: Kc
    ecc1_c = receive()
    Kc = decode64(ecc1_c["Kc"])
    
    # S -> C: {Kcs} Ks
    Kcs = get_random_bytes(16)
    ecc1_s = '{"id": "ECC1_S", "Kcs": "' + encode64( ecc_s.encrypt(Kcs, Kc) ) + '"}'
    send(ecc1_s)
    
    return Kcs
# end ECC_key_Exchange()


###################################################################################################


sym_alg = None
def SSL_HandShake():
    while True:
        h1 = receive()
        
        chosen_KE = "ECC"
        chosen_SYM = "AES"
        
        h2 = '{"id": "H_S", "text": "server hello", "KE": "' + chosen_KE + '", "SYM": "' + chosen_SYM + '"}'
        send(h2)
        
        sym_key = None
        if chosen_KE == "RSA":
            sym_key = RSA_keyExchange()
        
        elif chosen_KE == "ECC":
            sym_key = ECC_keyExchange()
        
        print("\nsent sym key:", sym_key)
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

try:
    SSL_HandShake()
finally:
    conn.close()

