import threading
import socket
import argparse
import tkinter as tk
from cryptography.fernet import Fernet

# Use the same key as in server.py
key = b'OPPIx8Z1wOjjWwMDqoFSiYpO2bDmaitCiVYn0uhwUWQ='
cipher_suite = Fernet(key)

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.username = None
        self.messages = None
        self.window = None

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print('Successfully connected to {}:{}'.format(self.host, self.port))
            self.login()
        except (socket.error, ConnectionError) as e:
            print(f"Socket connection error: {e}")
            return

    def login(self):
        login_window = tk.Tk()
        login_window.title("Login")

        tk.Label(login_window, text="Username:").pack()
        username_entry = tk.Entry(login_window)
        username_entry.pack()

        tk.Label(login_window, text="Password:").pack()
        password_entry = tk.Entry(login_window, show="*")
        password_entry.pack()

        def submit_login():
            username = username_entry.get()
            password = password_entry.get()
            try:
                if self.sock:
                    self.sock.sendall(username.encode('ascii'))
                    self.sock.sendall(password.encode('ascii'))
                    response = self.sock.recv(1024).decode('ascii')
                    if response == "AUTH_SUCCESS":
                        print("Login successful")
                        self.username = username
                        login_window.destroy()
                        self.setup_gui()
                    else:
                        print("Login failed")
                        self.sock.close()
            except (socket.error, ConnectionError) as e:
                print(f"Socket error during login: {e}")
                self.sock.close()

        tk.Button(login_window, text="Login", command=submit_login).pack()
        login_window.mainloop()

    def setup_gui(self):
        self.window = tk.Tk()
        self.window.title('Chatroom')

        from_message = tk.Frame(master=self.window)
        scroll_bar = tk.Scrollbar(master=from_message)
        messages = tk.Listbox(master=from_message, yscrollcommand=scroll_bar.set)
        scroll_bar.config(command=messages.yview)
        scroll_bar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
        messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.messages = messages

        from_message.grid(row=0, column=0, columnspan=2, sticky="nsew")
        from_entry = tk.Frame(master=self.window)
        text_input = tk.Entry(master=from_entry)

        text_input.pack(fill=tk.BOTH, expand=True)
        text_input.bind("<Return>", lambda x: self.send(text_input))
        text_input.insert(0, "Write your message here")

        btn_send = tk.Button(
            master=self.window,
            text='Send',
            command=lambda: self.send(text_input)
        )

        from_entry.grid(row=1, column=0, padx=10, sticky="ew")
        btn_send.grid(row=1, column=1, pady=10, sticky="ew")

        self.window.rowconfigure(0, minsize=500, weight=1)
        self.window.rowconfigure(1, minsize=50, weight=0)
        self.window.columnconfigure(0, minsize=500, weight=1)
        self.window.columnconfigure(1, minsize=50, weight=0)

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()

        # Start receiving messages after the GUI is set up
        receive_thread = Receive(self.sock, self)
        receive_thread.start()

    def send(self, text_input):
        if self.sock:
            message = text_input.get()
            text_input.delete(0, tk.END)
            encrypted_message = cipher_suite.encrypt(message.encode('ascii'))
            try:
                self.sock.sendall(encrypted_message)
            except (socket.error, ConnectionError) as e:
                print(f"Socket error during send: {e}")
                self.on_closing()

    def update_gui(self, message):
        if self.messages:
            self.messages.insert(tk.END, message)
            self.messages.yview(tk.END)  # Auto-scroll to the latest message

    def on_closing(self):
        print("Closing connection...")
        if self.sock:
            self.sock.close()
        if self.window:
            self.window.destroy()

class Receive(threading.Thread):
    def __init__(self, sock, client):
        super().__init__()
        self.sock = sock
        self.client = client

    def run(self):
        while True:
            try:
                encrypted_message = self.sock.recv(1024)
                if encrypted_message:
                    message = cipher_suite.decrypt(encrypted_message).decode('ascii')
                    # Ensure that GUI updates are on the main thread
                    self.client.window.after(0, self.client.update_gui, message)
            except (socket.error, ConnectionError) as e:
                print(f"Socket error during receive: {e}")
                self.client.on_closing()
                break

def main(host, port):
    client = Client(host, port)
    client.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom Client")
    parser.add_argument('host', help='Server host')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')
    args = parser.parse_args()
    main(args.host, args.p)
