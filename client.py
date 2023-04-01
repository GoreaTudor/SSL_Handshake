import socket
import time

messages = ["client hello", "client data", "client bye", "RST"]

if __name__ == '__main__':
    host = socket.gethostname()  # both apps running on same pc
    port = 5000
    client_socket = socket.socket()  # create new socket
    
    client_socket.connect((host, port))  # connect to the server
    print("Connected to server")
    
    index = 0
    
    while index < len(messages):
        message = messages[index]
        
        client_socket.send(message.encode())  # send message
        print("\nSent:", str(message))
        
        data = client_socket.recv(1024).decode()  # wait for server to send message
        print("Received:", str(data))
        
        time.sleep(0.5)  # sleeps in seconds
        index += 1  # prepare next message
    
    client_socket.close()  # close the connection
