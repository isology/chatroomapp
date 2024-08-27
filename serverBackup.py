import threading
import socket
import argparse
import os
from cryptography.fernet import Fernet
import sqlite3

class Server(threading.Thread):

    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.secret_key = Fernet.generate_key()  # One shared key for all clients
        self.cipher_suite = Fernet(self.secret_key)

        # Initialize database connection
        self.conn = sqlite3.connect('users.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                               (username TEXT PRIMARY KEY, password TEXT)''')

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print("Listening at ", sock.getsockname())

        while True:
            sc, sockname = sock.accept()
            print(f"Accepting a new connection from {sc.getpeername()} to {sc.getsockname()}")

            if self.handle_client(sc):
                server_socket = ServerSocket(sc, sockname, self)
                server_socket.start()
                self.connections.append(server_socket)
                print("Ready to receive messages from", sc.getpeername())
            else:
                sc.close()

    def handle_client(self, sc):
        try:
            action = sc.recv(1024).decode('ascii')
            if action == "REGISTER":
                return self.register(sc)
            elif action == "LOGIN":
                return self.authenticate(sc)
        except Exception as e:
            print(f"Error handling client: {e}")
            return False

    def register(self, sc):
        sc.sendall("NEW_USERNAME".encode('ascii'))
        username = sc.recv(1024).decode('ascii')
        sc.sendall("NEW_PASSWORD".encode('ascii'))
        password = sc.recv(1024).decode('ascii')

        self.cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        if self.cursor.fetchone():
            sc.sendall("USER_EXISTS".encode('ascii'))
            return False
        else:
            self.cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            self.conn.commit()
            sc.sendall("REGISTER_SUCCESS".encode('ascii'))
            sc.sendall(self.secret_key)  # Send the encryption key to the client
            return True

    def authenticate(self, sc):
        sc.sendall("LOGIN".encode('ascii'))
        username = sc.recv(1024).decode('ascii')
        sc.sendall("PASSWORD".encode('ascii'))
        password = sc.recv(1024).decode('ascii')

        self.cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        if self.cursor.fetchone():
            sc.sendall("SUCCESS".encode('ascii'))
            sc.sendall(self.secret_key)  # Send the encryption key to the client
            return True
        else:
            sc.sendall("FAILURE".encode('ascii'))
            return False

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
