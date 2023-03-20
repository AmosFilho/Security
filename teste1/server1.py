from chat_room import ChatServer, ChatClient
import threading
if __name__ == '__main__':
    # Define the host and port to use for the chat room
    HOST = 'localhost'
    PORT = 5000

    # Create an instance of the chat server
    server = ChatServer(HOST, PORT)
    server.start()

    # Create multiple instances of the chat client to join the chat room
    clients = [
        ChatClient(HOST, PORT),
        ChatClient(HOST, PORT),
        ChatClient(HOST, PORT),
        ChatClient(HOST, PORT),
    ]

    # Start each client in a separate thread
    for client in clients:
        threading.Thread(target=client.start).start()
