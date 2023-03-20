import socket
import threading
from tinyec import registry
import pickle
import secrets
import time
import chilkat2
import json

HEADER = 4096
PORT = 5050
SERVER = '127.0.0.1'
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "/exit"
ADDR = (SERVER, PORT)

client_list = []
current_active_users = []
database = json.load(open("user_database.txt"))
print(database)

server_crypt = chilkat2.Crypt2()
# region Chilkat2.Crypt configs
server_crypt.HashAlgorithm = "SHA256"
server_crypt.CryptAlgorithm = "twofish"
server_crypt.CipherMode = "cdc"
server_crypt.KeyLength = 256
server_crypt.PaddingScheme = 0
server_crypt.EncodingMode = "hex"
ivHex = "000102030405060708090A0B0C0D0E0F"
server_crypt.SetEncodedIV(ivHex, "hex")
# endregion

curve = registry.get_curve('brainpoolP256r1')
priv_key = secrets.randbelow(curve.field.n)
public_key = priv_key * curve.g

server_key = server_crypt.HashStringENC(str(secrets.randbelow(curve.field.n)))
'print("chave T: " + server_key, end="\n\n")'
'print("ECDH server public key: " + str(public_key.x), end="\n\n")'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


def broadcast(conn, sender, msg):
        for client in client_list:
            if client != conn:
                client.send(sender.encode(FORMAT))
                time.sleep(0.1)
                client.send(msg)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} joined the server")

    user_crypt = chilkat2.Crypt2()
    # region user_crypt configs
    user_crypt.HashAlgorithm = "SHA256"
    user_crypt.CryptAlgorithm = "twofish"
    user_crypt.CipherMode = "cdc"
    user_crypt.KeyLength = 256
    user_crypt.PaddingScheme = 0
    user_crypt.EncodingMode = "hex"
    ivHex = "000102030405060708090A0B0C0D0E0F"
    user_crypt.SetEncodedIV(ivHex, "hex")
    # endregion

    connected = True
    client_list.append(conn)

    try:
        shared_key = ecdh_routine(conn)
        user_crypt.SetEncodedKey(shared_key, 'hex')

        client_command_string = conn.recv(HEADER).decode(FORMAT)
        client_command = user_crypt.DecryptStringENC(client_command_string)

        if client_command == "/register":
            print(f"Client {addr} requested register operation")
            client_username_string = conn.recv(HEADER).decode(FORMAT)
            client_username = user_crypt.DecryptStringENC(client_username_string)
            client_password_string = conn.recv(HEADER).decode(FORMAT)
            client_password = user_crypt.DecryptStringENC(client_password_string)
            client_password_hashed = server_crypt.HashStringENC(client_password)
            if client_username not in database.keys():
                database[client_username] = client_password_hashed
                json.dump(database, open("user_database.txt", "w"), indent=4)
                response = "0"
            else:
                response = "1"
            response_encrypted = user_crypt.EncryptStringENC(response)
            conn.sendall(response_encrypted.encode(FORMAT))
            time.sleep(1)
            connected = False
            client_list.remove(conn)


        elif client_command == "/login":
            print(f"Client {addr} requested login operation")
            client_username_string = conn.recv(HEADER).decode(FORMAT)
            client_username = user_crypt.DecryptStringENC(client_username_string)
            client_password_string = conn.recv(HEADER).decode(FORMAT)
            client_password = user_crypt.DecryptStringENC(client_password_string)
            client_password_hashed = server_crypt.HashStringENC(client_password)
            if client_username in database.keys():
                match = client_password_hashed == database[client_username]
                if match:
                    if client_username in current_active_users:
                        response = "3"
                        connected = False
                    else:
                        response = "0"
                else:
                    response = "1"
                    connected = False
            else:
                response = "2"
                connected = False
            response_encrypted = user_crypt.EncryptStringENC(response)
            conn.sendall(response_encrypted.encode(FORMAT))
            if response == "0":
                send_twofish_key(conn, shared_key, user_crypt)
                message = '/connected'
                broadcast(conn, client_username, user_crypt.EncryptStringENC(message).encode(FORMAT))
                current_active_users.append(client_username)

    except Exception as e:
        print(e)
        print("Connection Interrupted")
        connected = False
        client_list.remove(conn)
        conn.close()

    while connected:
        try:
            msg = conn.recv(HEADER)
            if msg:
                if msg == DISCONNECT_MESSAGE:
                    client_list.remove(addr)
                    current_active_users.remove(client_username)
                    connected = False
                else:
                    broadcast(conn, client_username, msg)

                print(f"[{addr}] {msg.decode(FORMAT)}")
        except Exception as e:
            print(e)
            print(f"{client_username} disconnected")
            connected = False
            client_list.remove(conn)
            current_active_users.remove(client_username)
            conn.close()
    


def start():
    print("[STARTING] Server is starting...")
    server.listen()
    print(f'[SERVER] Server is listening to {SERVER}')
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


def ecdh_routine(conn):
    """Establishes secure shared key with connection, returns shared key"""
    curve_string = pickle.dumps(curve)
    public_key_string = pickle.dumps(public_key)
    conn.sendall(curve_string)
    time.sleep(1)
    conn.sendall(public_key_string)

    'Receiving client data'

    client_key_string = conn.recv(HEADER)

    'Creating ECDH shared key'
    client_key = pickle.loads(client_key_string)
    'print("ECDH client public key: " + str(client_key.x), end="\n\n")'
    shared_key_point = priv_key * client_key
    shared_key = server_crypt.HashStringENC(str(shared_key_point.x))

    return shared_key


def send_twofish_key(conn, key, crypt):
    """Sends server Twofish key to connection, using encryption key"""
    crypt.SetEncodedKey(key, 'hex')
    key_message = crypt.EncryptStringENC(server_key)
    time.sleep(1)
    conn.send(key_message.encode(FORMAT))
    crypt.SetEncodedKey(server_key, 'hex')


start()
