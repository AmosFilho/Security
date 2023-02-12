import servers as servers
import clientes as clients
if __name__ == '__main__':
    import threading 

    server_thread = threading.Thread(target=servers.start_server)
    client_thread = threading.Thread(target=clients.start_client)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()
