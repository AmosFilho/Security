# Cliente
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket

# Executa o protocolo de troca de chaves do Diffie-Hellman entre o cliente e o servidor
def diffie_hellman(conn):
    # Gerando as chaves
    p = 1234567891
    g = 2
    a = 987654321
    A = pow(g, a, p)

    # Enviando A para o servidor
    conn.send(str(A).encode())

    # Recebendo B do servidor
    B = int(conn.recv(1024).decode())

    # Calculando a chave compartilhada
    K = pow(B, a, p)
    return K

# Criptografa uma mensagem enviada pelo cliente usando o algoritmo ElGamal
def encrypt(message, key, pubkey):
    key = ElGamal.construct((long_to_bytes(key), pubkey))
    ciphertext = key.encrypt(message.encode())
    return ciphertext

# Descriptografa uma mensagem recebida pelo servidor usando o algoritmo ElGamal
def decrypt(key, pubkey, ciphertext):
    key = ElGamal.construct((long_to_bytes(key), pubkey))
    plaintext = key.decrypt(ciphertext)
    return plaintext.decode()

# Função principal do cliente
def client():
    # Criando o socket
    host = '127.0.0.1'
    port = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conectando ao servidor
    s.connect((host, port))
    print(f"Conectado ao servidor {host}:{port}")

    # Executando o protocolo de troca de chaves com o servidor
    K = diffie_hellman(s)

    # Recebendo a chave pública do servidor
    pubkey = s.recv(1024)

    # Aguardando mensagens do servidor
    while True:
        # Lendo a mensagem enviada pelo cliente
        message = input("Digite uma mensagem para enviar ao servidor: ")

        # Criptografando a mensagem usando a chave compartilhada
        ciphertext = encrypt(message, K, pubkey)

        # Enviando a mensagem criptografada para o servidor
        s.send(ciphertext)

        # Recebendo a mensagem criptografada do servidor
        ciphertext = s.recv(1024)

        # Descriptografando a mensagem recebida
        plaintext = decrypt(K, pubkey, ciphertext)

        print(f"Mensagem recebida do servidor: {plaintext}")

        # Verificando se o usuário quer encerrar a conexão
        end = input("Deseja encerrar a conexão? (s/n)")

        if end.lower() == "s":
            # Fechando a conexão
            s.close()
            print("Conexão encerrada")
            break

# Chamando a função principal do cliente
if __name__ == "__main__":
    client()
