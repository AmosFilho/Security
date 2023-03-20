import random
import sys
import socket

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_exp(b, e, m):
    result = 1
    while e > 0:
        if e % 2 == 1:
            result = (result * b) % m
        e = e // 2
        b = (b * b) % m
    return result

def key_exchange(p, g, a):
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)
    s = mod_exp(B, a, p)
    return s

def rc4_encrypt(data, key):
    S = list(range(256))
    j = 0
    out = []
    for i in range(len(data)):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(data[i]) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)

def rc4_decrypt(data, key):
    return rc4_encrypt(data, key)


p = random.randint(100, 1000)
g = random.randint(2, p-1)
a = random.randint(1, p-1)
b = random.randint(1, p-1)
s = key_exchange(p, g, a)

def server():
    # Diffie-Hellman Key Exchange
    print("Entradas para o servidor:")
    print("p: %d" % p)
    print("g: %d" % g)
    print("a: %d" % a)
    print("Chave compartilhada: %d" % s) # Criação do socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)

    print("Aguardando conexão do cliente...")
    client_socket, client_address = server_socket.accept()
    print("Conexão estabelecida com %s:%d" % client_address)

    # Envio da chave compartilhada para o cliente
    client_socket.send(str(s).encode())

    # Recebimento de mensagens do cliente
    while True:
        data = client_socket.recv(4096)
        if not data:
            break
        data = data.decode()
        print("Mensagem recebida: %s" % data)

        # Criptografia da mensagem com RC4
        key = str(s).encode()
        encrypted_data = rc4_encrypt(data, key)
        print("Mensagem criptografada: %s" % encrypted_data)

        # Re-geração da chave RC4
        key = str(random.getrandbits(128)).encode()

        # Envio da mensagem criptografada para o cliente
        client_socket.send(encrypted_data.encode())

def client():
    # Diffie-Hellman Key Exchange
    print("\nEntradas para o cliente:")
    print("p: %d" % p)
    print("g: %d" % g)
    print("b: %d" % b)

    # Criação do socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Recebimento da chave compartilhada do servidor
    s = int(client_socket.recv(4096).decode())
    print("Chave compartilhada recebida: %d" % s)

    # Envio de mensagens para o servidor
    while True:
        data = input("Digite sua mensagem: ")
        if not data:
            break

        # Criptografia da mensagem com RC4
        key = str(s).encode()
        encrypted_data = rc4_encrypt(data, key)
        print("Mensagem criptografada: %s" % encrypted_data)

        # Re-geração da chave RC4
        key = str(random.getrandbits(128)).encode()

        # Envio da mensagem criptografada para o servidor
        client_socket.send(encrypted_data.encode())

        # Recebimento da mensagem criptografada do servidor
        data = client_socket.recv(4096)
        if not data:
            break
        data = data.decode()
        print("Mensagem recebida do servidor: %s" % data)
                # Descriptografia da mensagem com RC4
        decrypted_data = rc4_decrypt(data, key)
        print("Mensagem descriptografada: %s" % decrypted_data)

# Execução do programa
if __name__ == "__main__":
    process = input("Você quer ser o servidor (s) ou o cliente (c)? ")
    if process == 's':
        server()
    elif process == 'c':
        client()
    else:
        print("Opção inválida. Tente novamente.")
