import threading
import socket
import argparse
import os
from cryptography.fernet import Fernet

# Use the generated key here
key = b'OPPIx8Z1wOjjWwMDqoFSiYpO2bDmaitCiVYn0uhwUWQ='
cipher_suite = Fernet(key)

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.lock = threading.Lock()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print("Listening at", sock.getsockname())

        while True:
            sc, _ = sock.accept()
            print(f"Accepted connection from {sc.getpeername()}")

            client_thread = ClientHandler(sc, self)
            client_thread.start()
            with self.lock:
                self.connections.append(client_thread)

    def broadcast(self, message, source):
        encrypted_message = cipher_suite.encrypt(message.encode('ascii'))
        with self.lock:
            for connection in self.connections:
                if connection.client_socket != source:
                    connection.send(encrypted_message)

    def remove_connection(self, connection):
        with self.lock:
            if connection in self.connections:
                self.connections.remove(connection)

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, server):
        super().__init__()
        self.client_socket = client_socket
        self.server = server
        self.username = None

    def run(self):
        if not self.authenticate():
            self.client_socket.close()
            return

        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    message = cipher_suite.decrypt(encrypted_message).decode('ascii')
                    print(f"Received message: {message}")
                    self.server.broadcast(message, self.client_socket)
                else:
                    break
            except ConnectionResetError:
                break

        print(f"{self.username} has disconnected")
        self.client_socket.close()
        self.server.remove_connection(self)

    def authenticate(self):
        valid_users = {
            "admin": "password123",
            "user1": "password456",
            "user2": "password789"
        }

        username = self.client_socket.recv(1024).decode('ascii').strip()
        password = self.client_socket.recv(1024).decode('ascii').strip()
        print(f"Authenticating {username}")

        if username in valid_users and valid_users[username] == password:
            self.username = username
            self.client_socket.sendall("AUTH_SUCCESS".encode('ascii'))
            return True
        else:
            self.client_socket.sendall("AUTH_FAILED".encode('ascii'))
            return False

    def send(self, message):
        self.client_socket.sendall(message)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom Server")
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')
    args = parser.parse_args()

    server = Server(args.host, args.p)
    server.start()
