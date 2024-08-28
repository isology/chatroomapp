import socket

def test_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 1060))
    client.sendall("UPDATE".encode('ascii'))
    response = client.recv(1024).decode('ascii')
    print("Server response:", response)
    client.close()

if __name__ == "__main__":
    test_client()
