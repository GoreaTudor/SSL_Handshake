import socket
import time

messages = ["server hello", "server data", "server bye", "RST ACK"]

if __name__ == '__main__':
    host = socket.gethostname()  # both apps running on same pc
    port = 5000
    server_socket = socket.socket()  # create new socket
    server_socket.bind((host, port))  # binds host address and port together
    
    server_socket.listen(1)  # config how many clients the server can listen to
    print("Server started")
    
    conn, adr = server_socket.accept()  # accept new connection to client
    print("Connection accepted, address is:", str(adr))
    
    index = 0
    
    while True:
        data = conn.recv(1024).decode()  # receive data from client
        print("\nReceived:", str(data))
        
        # process message and prepare answer...
        if not data:
            break  # if data is not received, then break
        
        message = messages[index]  # prepare message
        time.sleep(0.5)
        index += 1

        conn.send(message.encode())  # send message to client
        print("Sent:", str(message))
    
    conn.close()
