import socket

host = "192.168.138.60"
port = 8080
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
message = 'hello'
client_socket.sendall(message.encode())
client_socket.close()