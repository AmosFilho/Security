import pickle
import socket
import secrets
from threading import Thread
from tinyec import registry
import time
import chilkat2

HEADER = 4096
PORT = 5050
SERVER = "127.0.0.1"
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "/exit"
ADDR = (SERVER, PORT)

# region chilkat2 Crypt
crypt = chilkat2.Crypt2()
crypt.HashAlgorithm = "SHA256"
crypt.CryptAlgorithm = "twofish"
crypt.CipherMode = "cdc"
crypt.KeyLength = 256
crypt.PaddingScheme = 0
crypt.EncodingMode = "hex"
ivHex = "000102030405060708090A0B0C0D0E0F"
crypt.SetEncodedIV(ivHex,"hex")
# endregion

blocklist = []

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Connecting to server...')
client.connect(ADDR)


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


def ecdh_routine():
    print('Receiving server data...')
    curve_string = client.recv(HEADER)
    server_public_key_string = client.recv(HEADER)

    'Creating ECDH shared key'
    curve = pickle.loads(curve_string)
    server_public_key = pickle.loads(server_public_key_string)
    'print("ECDH server public key: " + str(server_public_key.x), end="\n\n")'
    priv_key = secrets.randbelow(curve.field.n)
    pub_key = priv_key * curve.g
    'print("ECDH client public key: " + str(pub_key.x), end="\n\n")'
    shared_key_point = priv_key * server_public_key
    shared_key = crypt.HashStringENC(str(shared_key_point.x))
    'print("ECDH shared key (S): " + secretkey, end="\n\n")'

    print('Sending client data')
    pub_key_string = pickle.dumps(pub_key)
    time.sleep(1)
    client.send(pub_key_string)

    return shared_key


def receive_twofish_key(key):
    """Receives twofish key, using key to decrypt message"""
    crypt.SetEncodedKey(key, 'hex')
    server_key_encrypted = client.recv(HEADER).decode(FORMAT)
    server_key = crypt.DecryptStringENC(server_key_encrypted)
    print("server key (T): " + server_key, end="\n\n")
    crypt.SetEncodedKey(server_key, 'hex')


def send(msg):
    message = crypt.EncryptStringENC(msg)
    client.send(message.encode(FORMAT))

def blacklist(user):
    if user not in blocklist:
        blocklist.append(user)
    else:
        blocklist.remove(user)
    print(f'[COMMAND] Blacklisted "{user}" ')


def listen():
    connected = True
    print('Connected to Server.')
    while connected:
        received_message_sender = client.recv(HEADER).decode(FORMAT)
        received_message_encrypted = client.recv(HEADER).decode(FORMAT)
        received_message = crypt.DecryptStringENC(received_message_encrypted)
        if received_message == "/connected":
            print(f"[SERVER] {received_message_sender} has entered the chat")
        elif received_message_sender not in blocklist:
            print(f'{received_message_sender}: {received_message}')

try:
    shared_key = ecdh_routine()
    crypt.SetEncodedKey(shared_key, 'hex')
except:
    print("no response from server...")

user_command = True
connected = True
command = ""
while user_command:
    print("Insert Command (/register (username) (password), /login (username) (password), /disconnect)")
    command = input("Command: ")
    command_params = command.split(" ")
    if command_params[0] == '/register':
        username = command_params[1]
        password = command_params[2]
        try:
            send(command_params[0])
            time.sleep(1)
            send(username)
            time.sleep(1)
            send(password)
            response_msg = client.recv(HEADER).decode(FORMAT)
            response = crypt.DecryptStringENC(response_msg)
            if response == "0":
                print("Operation successful")
            elif response == "1":
                print("Operation Failed, user already registered")
            else:
                print("Operation Failed, no response")
            client.close()
            user_command = False
            connected = False
        except:
            print("command failed")
    elif command_params[0] == '/login':
        username = command_params[1]
        password = command_params[2]
        try:
            send(command_params[0])
            time.sleep(1)
            send(username)
            time.sleep(1)
            send(password)
            response_msg = client.recv(HEADER).decode(FORMAT)
            response = crypt.DecryptStringENC(response_msg)
            if response == "0":
                print("Logged in")
                user_command = False
                receive_twofish_key(shared_key)
            elif response == "1":
                print("Operation Failed, wrong password")
                user_command = False
                connected = False
            elif response == "2":
                print(f"Operation Failed, no user with the name \"{username}\"")
                user_command = False
                connected = False
            elif response == "3":
                print(f"Operation Failed, user already logged in another place")
                user_command= False
                connected = False
            else:
                print("No response")
                connected = False
                user_command = False
                print(response)
        except:
            print("command failed")


if connected:
    t = Thread(target=listen)
    t.start()
    msg = ''
    while msg != DISCONNECT_MESSAGE:
        msg = input()
        msg_param = msg.split(' ')
        if msg_param[0] == '/blacklist':
            if msg_param[1]:
                blacklist(msg_param[1])
        else:
            send(msg)
    connected = False
input()


