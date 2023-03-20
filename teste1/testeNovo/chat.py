from Crypto.PublicKey import ElGamal
from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket
from Crypto.Random import get_random_bytes

# Gera as chaves públicas e privadas do ElGamal para o servidor


def generate_keys():
    key = ElGamal.generate(1024, get_random_bytes)
    return key.publickey(), key

# Executa o protocolo de troca de chaves do Diffie-Hellman entre o servidor e o cliente


def diffie_hellman(conn):
    # Gerando as chaves
    p = 1234567891
    g = 2
    b = 123456789
    B = pow(g, b, p)

    # Recebendo A do cliente
    A = int(conn.recv(1024).decode())

    # Enviando B para o cliente
    conn.send(str(B).encode())

    # Calculando a chave compartilhada
    K = pow(A, b, p)
    return K

# Criptografa uma mensagem enviada pelo cliente usando o algoritmo ElGamal


def encrypt(message, key, pubkey):
    key = ElGamalCipher.construct((long_to_bytes(key), pubkey))
    ciphertext = key.encrypt(message.encode())
    return ciphertext

# Descriptografa uma mensagem recebida pelo servidor usando o algoritmo ElGamal


def decrypt(key, pubkey, ciphertext):
    key = ElGamalCipher.construct((long_to_bytes(key), pubkey))
    plaintext = key.decrypt(ciphertext)
    return plaintext.decode()

# Função principal do servidor


def server():
    # Criando o socket
    host = '127.0.0.1'
    port = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Servidor escutando em {host}:{port}...")

    # Gerando as chaves púb
    pubkey, key = generate_keys()


    # Aguardando conexão do cliente
    conn, addr = s.accept()
    print(f"Conexão estabelecida com {addr}")

    # Executando o protocolo de troca de chaves com o cliente
    K = diffie_hellman(conn)

    # Aguardando mensagens do cliente
    while True:
        ciphertext = conn.recv(1024)
        if not ciphertext:
            break

        # Descriptografando a mensagem recebida
        plaintext = decrypt(K, pubkey, ciphertext)

        print(f"Mensagem recebida do cliente: {plaintext}")

        # Lendo a mensagem enviada pelo servidor
        message = input("Digite uma mensagem para enviar ao cliente: ")

        # Criptografando a mensagem usando a chave compartilhada
        ciphertext = encrypt(message, K, pubkey)

        # Enviando a mensagem criptografada para o cliente
        conn.send(ciphertext)

    # Fechando a conexão
    conn.close()
    print("Conexão encerrada")
# Chamando a função principal do cliente
if __name__ == "__main__":
    server()
