import socket

IP = "localhost"
PORT = 8080

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, PORT))

while True:
    msg = input("Digite sua mensagem: ")
    client.send(msg.encode())
    resp = client.recv(1024).decode()
    print(f"Resposta: {resp}")

client.close()