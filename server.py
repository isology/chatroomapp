# server.py
import threading
import socket
import argparse
import sqlite3
from cryptography.fernet import Fernet

class Server(threading.Thread):

    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.secret_key = Fernet.generate_key()  # One shared key for all clients
        self.cipher_suite = Fernet(self.secret_key)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print("Listening at ", sock.getsockname())

        while True:
            sc, sockname = sock.accept()
            print(f"Accepting a new connection from {sc.getpeername()} to {sc.getsockname()}")

            # Handle login
            if self.authenticate(sc):
                server_socket = ServerSocket(sc, sockname, self)
                server_socket.start()
                self.connections.append(server_socket)
                print("Ready to receive messages from", sc.getpeername())
            else:
                sc.close()

    def authenticate(self, sc):
        sc.sendall("LOGIN".encode('ascii'))
        username = sc.recv(1024).decode('ascii')
        sc.sendall("PASSWORD".encode('ascii'))
        password = sc.recv(1024).decode('ascii')

        # Check credentials from the database
        if self.check_credentials(username, password):
            sc.sendall("SUCCESS".encode('ascii'))
            sc.sendall(self.secret_key)  # Send the encryption key to the client
            return True
        else:
            sc.sendall("FAILURE".encode('ascii'))
            return False

    def check_credentials(self, username, password):
        conn = sqlite3.connect('chat_users.db')
        cursor = conn.cursor()

        # Query to check if the user exists and password matches
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        result = cursor.fetchone()
        conn.close()

        return result is not None

    def broadcast(self, message, source):
        encrypted_message = self.cipher_suite.encrypt(message.encode('ascii'))
        for connection in self.connections:
            if connection.sockname != source:
                connection.send(encrypted_message)

    def removeConnection(self, connection):
        self.connections.remove(connection)


class ServerSocket(threading.Thread):

    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server

    def run(self):
        while True:
            encrypted_message = self.sc.recv(1024)
            message = self.server.cipher_suite.decrypt(encrypted_message).decode('ascii')

            if message:
                print(f"{self.sockname} says {message}")
                self.server.broadcast(message, self.sockname)
            else:
                print(f"{self.sockname} has closed the connection")
                self.sc.close()
                self.server.removeConnection(self)
                return

    def send(self, message):
        self.sc.sendall(message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom Server")
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port(default 1060)')

    args = parser.parse_args()

    server = Server(args.host, args.p)
    server.start()