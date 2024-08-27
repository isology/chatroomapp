import threading
import socket
import argparse
import os
import sys
import tkinter as tk
from cryptography.fernet import Fernet

class Send(threading.Thread):
    def __init__(self, sock, name, cipher_suite):
        super().__init__()
        self.sock = sock
        self.name = name
        self.cipher_suite = cipher_suite

    def run(self):
        while True:
            print('{}: '.format(self.name), end='')
            sys.stdout.flush()
            message = sys.stdin.readline()[:-1]

            if message == "QUIT":
                encrypted_message = self.cipher_suite.encrypt(
                    'Server: {} has left the chat.'.format(self.name).encode('ascii'))
                self.sock.sendall(encrypted_message)
                break
            else:
                encrypted_message = self.cipher_suite.encrypt(
                    '{}: {}'.format(self.name, message).encode('ascii'))
                self.sock.sendall(encrypted_message)

        print('\nQuitting...')
        self.sock.close()
        os._exit(0)

class Receive(threading.Thread):
    def __init__(self, sock, name, cipher_suite):
        super().__init__()
        self.sock = sock
        self.name = name
        self.cipher_suite = cipher_suite
        self.messages = None

    def run(self):
        while True:
            try:
                encrypted_message = self.sock.recv(1024)
                if not encrypted_message:
                    # Handle connection closure
                    print('\nWe have lost connection to the server!')
                    print('\nQuitting...')
                    self.sock.close()
                    os._exit(0)

                message = self.cipher_suite.decrypt(encrypted_message).decode('ascii')

                if self.messages:
                    self.messages.insert(tk.END, message)
                else:
                    print('\r{}\n{}: '.format(message, self.name), end='')
            except Exception as e:
                print(f"Error receiving message: {e}")
                break


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.messages = None
        self.cipher_suite = None

    def start(self):
        print('Trying to connect to {}:{}...'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))
        print('Successfully connected to {}:{}'.format(self.host, self.port))

    def choose_login_or_register(self):
        window = tk.Tk()
        window.title('Login or Register')

        def set_choice(choice):
            self.choice = choice
            window.destroy()

        tk.Button(window, text="Login", command=lambda: set_choice('LOGIN')).pack()
        tk.Button(window, text="Register", command=lambda: set_choice('REGISTER')).pack()

        window.mainloop()

        return self.choice

    def register(self, username, password):
        self.sock.sendall("REGISTER".encode('ascii'))
        server_message = self.sock.recv(1024).decode('ascii')
        if server_message == "NEW_USERNAME":
            self.sock.sendall(username.encode('ascii'))
        server_message = self.sock.recv(1024).decode('ascii')
        if server_message == "NEW_PASSWORD":
            self.sock.sendall(password.encode('ascii'))

        server_message = self.sock.recv(1024).decode('ascii')
        if server_message == "USER_EXISTS":
            print("Username already exists!")
            return False
        elif server_message == "REGISTER_SUCCESS":
            print("Registered successfully!")
            self.cipher_suite = Fernet(self.sock.recv(1024))  # Receive the shared encryption key
            return True
        return False

    def login(self, username, password):
        self.sock.sendall("LOGIN".encode('ascii'))
        server_message = self.sock.recv(1024).decode('ascii')
        if server_message == "LOGIN":
            self.name = username
            self.sock.sendall(self.name.encode('ascii'))

        server_message = self.sock.recv(1024).decode('ascii')
        if server_message == "PASSWORD":
            self.sock.sendall(password.encode('ascii'))

            server_message = self.sock.recv(1024).decode('ascii')
            if server_message == "SUCCESS":
                print("Logged in successfully!")
                self.cipher_suite = Fernet(self.sock.recv(1024))  # Receive the shared encryption key
                return True
            else:
                print("Login failed!")
                return False
        return False

    def send(self, textInput):
        message = textInput.get()
        textInput.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, message))

        if message == "QUIT":
            encrypted_message = self.cipher_suite.encrypt(
                'Server: {} has left the chat.'.format(self.name).encode('ascii'))
            self.sock.sendall(encrypted_message)
            print('\nQuitting...')
            self.sock.close()
            os._exit(0)
        else:
            encrypted_message = self.cipher_suite.encrypt(
                '{}: {}'.format(self.name, message).encode('ascii'))
            self.sock.sendall(encrypted_message)

def chat_window(client):
    window = tk.Tk()
    window.title('Chatroom')

    fromMessage = tk.Frame(master=window)
    scrollBar = tk.Scrollbar(master=fromMessage)
    messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set)
    scrollBar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    client.messages = messages
    receive = Receive(client.sock, client.name, client.cipher_suite)
    receive.messages = messages
    receive.start()

    fromMessage.grid(row=0, column=0, columnspan=2, sticky="nsew")
    fromEntry = tk.Frame(master=window)
    textInput = tk.Entry(master=fromEntry)

    textInput.pack(fill=tk.BOTH, expand=True)
    textInput.bind("<Return>", lambda x: client.send(textInput))
    textInput.insert(0, "Write your message here")

    btnSend = tk.Button(
        master=window,
        text='Send',
        command=lambda: client.send(textInput)
    )

    fromEntry.grid(row=1, column=0, padx=10, sticky="ew")
    btnSend.grid(row=1, column=1, pady=10, sticky="ew")

    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=50, weight=0)

    window.mainloop()

def main(host, port):
    client = Client(host, port)
    client.start()

    choice = client.choose_login_or_register()

    window = tk.Tk()
    window.title('Register' if choice == 'REGISTER' else 'Login')

    tk.Label(window, text="Username").grid(row=0)
    tk.Label(window, text="Password").grid(row=1)

    username_entry = tk.Entry(window)
    password_entry = tk.Entry(window, show="*")

    username_entry.grid(row=0, column=1)
    password_entry.grid(row=1, column=1)

    def attempt_authentication():
        username = username_entry.get()
        password = password_entry.get()
        if choice == 'REGISTER':
            if client.register(username, password):
                window.destroy()
                chat_window(client)
            else:
                tk.Label(window, text="Registration failed, try again!").grid(row=3, columnspan=2)
        elif choice == 'LOGIN':
            if client.login(username, password):
                window.destroy()
                chat_window(client)
            else:
                tk.Label(window, text="Login failed, try again!").grid(row=3, columnspan=2)

    auth_button = tk.Button(window, text="Submit", command=attempt_authentication)
    auth_button.grid(row=2, columnspan=2)

    window.mainloop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom Client")
    parser.add_argument('host', help='Host to connect to')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')

    args = parser.parse_args()

    main(args.host, args.p)
