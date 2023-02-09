import random
import hashlib
import socket

# Função hash para garantir a segurança
def hash(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

# Definição dos parâmetros do algoritmo
p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        "fffffffffffff", 16)
g = 2

alice_private = random.randint(0, p)

bob_private = random.randint(0, p)

# Cálculo da chave pública
alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)

# Cálculo da chave compartilhada
alice_shared = pow(bob_public, alice_private, p)
bob_shared = pow(alice_public, bob_private, p)

# Verificação da igualdade das chaves compartilhadas
assert alice_shared == bob_shared

# Cálculo da chave de cifra
alice_key = hash(str(alice_shared))
bob_key = hash(str(bob_shared))

# Verificação da igualdade das chaves de cifra
assert alice_key == bob_key

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conectar ao servidor
server_address = ('localhost', 12345)
client_socket.connect(server_address)

# Escolha da chave privada
private_key = random.randint(0, p)

# Cálculo da chave pública
public_key = pow(g, private_key, p)

client_socket.sendall(str(public_key).encode())

# Receber a chave pública do servidor
server_public_key = int(client_socket.recv(4096).decode())

# Cálculo da chave compartilhada
shared_key = pow(server_public_key, private_key, p)

# Cálculo da chave de cifra
key = hash(str(shared_key))

# Fechar a conexão com o servidor
client_socket.close()

def rc4(data, key):
    S = list(range(256))
    j = 0
    out = bytearray()

    # Inicialização
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Geração de fluxo de chave
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

key = b'chavesecreta'
data = b'mensagemsecreta'
ciphertext = rc4(data, key)
print(ciphertext)