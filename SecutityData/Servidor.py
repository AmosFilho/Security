import socket

IP = "localhost"
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IP, PORT))
server.listen()

print(f"Servidor escutando em {IP}:{PORT}")

client_socket, client_address = server.accept()
print(f"Conexão estabelecida com {client_address}")

while True:
    msg = client_socket.recv(1024).decode()
    if not msg:
        break
    print(f"Mensagem recebida: {msg}")
    client_socket.send(b"Mensagem recebida")

client_socket.close()