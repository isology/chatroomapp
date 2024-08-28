import socket

def test_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 1060))
    server.listen(1)
    print("Server listening...")
    conn, addr = server.accept()
    print("Connection from:", addr)
    data = conn.recv(1024).decode('ascii')
    print("Received from client:", data)
    if data == "UPDATE":
        conn.sendall("UPDATE".encode('ascii'))
    conn.close()
    server.close()

if __name__ == "__main__":
    test_server()
