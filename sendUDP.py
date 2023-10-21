import socket

host = "192.168.138.134"
port = 8080
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

message = 'hello'
client_socket.sendto(message.encode(), (host, port))
client_socket.close()
