import socket
import json
import base64
from Crypto.Random import get_random_bytes
from pub_RSA import KE_RSA
from pub_ECC import KE_ECC
import sym_AES

class SSLServer:
    def __init__(self, host, port, update_output_callback=None):
        self.host = host
        self.port = port
        self.update_output_callback = update_output_callback
        self.server_socket = socket.socket()

    def receive(self):
        """
        Receives data from the client and returns the received message.

        :return: The received message
        :rtype: dict
        """
        data = self.conn.recv(2048).decode()

        if not data:
            self.conn.close()
            quit()

        print("\nReceived:", str(data))

        if self.update_output_callback:
            self.update_output_callback(f"\nReceived: {str(data)}")

        return json.loads(data)


    def send(self, message):
        """
        Sends a message to the client.

        :param message: The message to send
        :type message: str
        """
        self.conn.send(message.encode())
        print("Sent:", str(message))

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
        Performs RSA key exchange with the client.

        :return: The symmetric key
        :rtype: bytes
        """
        print("\nRSA Key Exchange:")

        rsa_s = KE_RSA()

        rsa1_c = self.receive()
        Kc = self.decode64(rsa1_c["Kc"])

        Kcs = get_random_bytes(16)
        rsa1_s = {"id": "RSA1_S", "Kcs": self.encode64(rsa_s.encrypt(Kcs, Kc))}
        self.send(json.dumps(rsa1_s))

        return Kcs

    def ecc_key_exchange(self):
        """
        Performs ECC key exchange with the client.

        :return: The symmetric key
        :rtype: bytes
        """
        print("\nECC Key Exchange:")

        ecc_s = KE_ECC()

        ecc1_c = self.receive()
        Kc = self.decode64(ecc1_c["Kc"])

        Kcs = get_random_bytes(16)
        ecc1_s = {"id": "ECC1_S", "Kcs": self.encode64(ecc_s.encrypt(Kcs, Kc))}
        self.send(json.dumps(ecc1_s))

        return Kcs

    def ssl_handshake(self):
        """
        Performs SSL handshake with the client.
        """
        while True:
            h1 = self.receive()

            chosen_ke = "ECC"
            chosen_sym = "AES"

            h2 = {
                "id": "H_S", 
                "text": "server hello", 
                "KE": chosen_ke, 
                "SYM": chosen_sym
            }

            self.send(json.dumps(h2))

            if chosen_ke == "RSA":
                sym_key = self.rsa_key_exchange()
            elif chosen_ke == "ECC":
                sym_key = self.ecc_key_exchange()

            print("\nSent symmetric key:", sym_key)
            
            if self.update_output_callback:
                self.update_output_callback(f"\nSent symmetric key: {sym_key}")

    def run(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)

        print("Server started")

        self.conn, adr = self.server_socket.accept()

        print("Connection accepted, address is:", str(adr))

        if self.update_output_callback:
            self.update_output_callback("Server started")
            self.update_output_callback(f"Connection accepted, address is: {str(adr)}")

        try:
            self.ssl_handshake()
        finally:
            self.conn.close()

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
    ssl_server = SSLServer(host, port)
    ssl_server.run()
