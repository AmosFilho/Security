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

def client():
    # Diffie-Hellman Key Exchange
    p = int(input("Digite o valor de p: "))
    g = int(input("Digite o valor de g: "))
    b = random.randint(1, p-1)

    print("Chaves privadas: ")
    print("a: %d" % b)

    # Criação do socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Enviar p, g, e b para o servidor
    client_socket.send(str(p).encode())
    client_socket.send(str(g).encode())
    client_socket.send(str(b).encode())

    # Receber chave compartilhada s do servidor
    s = int(client_socket.recv(4096).decode())
    print("Chave compartilhada: %d" % s)

    # Enviar mensagem criptografada para o servidor
    while True:
        data = input("Digite sua mensagem: ")
        if not data:
            break

        # Criptografia da mensagem com RC4
        key = str(s).encode()
        encrypted_data = rc4_encrypt(data, key)
        print("Mensagem criptografada: %s" % encrypted_data)

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

    # Fechamento do socket
    client_socket.close()

# Execução do programa
if __name__ == "__main__":
    client()
