import socket
import json
import base64
from Crypto.Random import get_random_bytes
from pub_RSA import KE_RSA
from pub_ECC import KE_ECC
import sym_AES

class SSLClient:
    def __init__(self, host, port, update_output_callback=None):
        self.host = host
        self.port = port
        self.update_output_callback = update_output_callback
        self.client_socket = socket.socket()

    def send_receive(self, message):
        """
        Sends a message to the server and returns the server's response.
        
        :param message: The message to send
        :type message: str
        :return: The server's response
        :rtype: dict
        """
        self.client_socket.send(message.encode())
        print("\nSent:", str(message))

        if self.update_output_callback:
            self.update_output_callback(f"\nSent: {str(message)}")

        data = self.client_socket.recv(2048).decode()
        print("Received:", str(data))

        if self.update_output_callback:
            self.update_output_callback(f"\nReceived: {str(message)}")

        return json.loads(data)

    @staticmethod
    def encode64(byte_string):
        """
        Encodes a byte string to a base64 string.
        
        :param byte_string: The byte string to encode
        :type byte_string: bytes
        :return: The base64 encoded string
        :rtype: str
        """
        return base64.b64encode(byte_string).decode("UTF-8")

    @staticmethod
    def decode64(string):
        """
        Decodes a base64 string to a byte string.
        
        :param string: The base64 string to decode
        :type string: str
        :return: The decoded byte string
        :rtype: bytes
        """
        return base64.b64decode(string.encode("UTF-8"))

    def rsa_key_exchange(self):
        """
        Performs RSA key exchange with the server.
        
        :return: The symmetric key
        :rtype: bytes
        """
        print("\nRSA Key Exchange:")

        rsa_c = KE_RSA()
        Kc = rsa_c.getPublicKey()
        rsa1_c = {"id": "RSA1_C", "Kc": self.encode64(Kc)}

        rsa1_s = self.send_receive(json.dumps(rsa1_c))
        Kcs = rsa_c.decrypt(self.decode64(rsa1_s["Kcs"]))

        return Kcs

    def ecc_key_exchange(self):
        """
        Performs ECC key exchange with the server.
        
        :return: The symmetric key
        :rtype: bytes
        """
        print("\nECC Key Exchange:")

        ecc_c = KE_ECC()
        Kc = ecc_c.getPublicKey()
        ecc1_c = {"id": "ECC1_C", "Kc": self.encode64(Kc)}

        ecc1_s = self.send_receive(json.dumps(ecc1_c))
        Kcs = ecc_c.decrypt(self.decode64(ecc1_s["Kcs"]))

        return Kcs

    def ssl_handshake(self):
        """
        Performs SSL handshake with the server.
        """
        h_c = {
            "id": "H_C", 
            "text": "client hello", 
            "KE": [
                "ECC", 
                "RSA"
            ], 
            "SYM": [
                "AES", 
                "Blowfish"
            ]
        }

        h_s = self.send_receive(json.dumps(h_c))

        chosen_ke = h_s["KE"]
        chosen_sym = h_s["SYM"]

        if chosen_ke == "RSA":
            sym_key = self.rsa_key_exchange()
        elif chosen_ke == "ECC":
            sym_key = self.ecc_key_exchange()

        print("\nReceived symmetric key:", sym_key)
        
        if self.update_output_callback:
            self.update_output_callback(f"Received symmetric key: {sym_key}")

    def run(self):
        self.client_socket.connect((self.host, self.port))

        print("Connected to server")

        if self.update_output_callback:
            self.update_output_callback("Connected to server")

        try:
            self.ssl_handshake()
        finally:
            self.client_socket.close()

def read_config():
    with open("config.json", "r") as file:
        config = json.load(file)
    return config

if __name__ == "__main__":
    config = read_config()
    host = socket.gethostname()
    print(host)
    port = config["port"]
    print(port)
    ssl_client = SSLClient(host, port)
    ssl_client.run()
