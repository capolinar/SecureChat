import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

CLIENT_LIST = []


def chat_server_single():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    conn, address = server_socket.accept()
    with conn:
        print(f'Connected by user at address {address}')
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)


def chat_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    def broadcast(message):
        for client in CLIENT_LIST:
            client.send(message.encode('utf-8'))

    def handle(conn):
        while True:
            try:
                message = conn.recv(1024)
                broadcast(message)
            except:
                CLIENT_LIST.remove(conn)
                conn.close()
                print(f'A connection has been removed')
                break

    while True:
        conn, address = server_socket.accept()
        print(f'Connected with user at address {address}')

        CLIENT_LIST.append(conn)
        conn.send(f'You have connected to the server!'.encode('utf-8'))
        broadcast(f'User has joined the chat!')

        thread = threading.Thread(target=handle, args=(conn,))
        thread.start()


def main():
    print('Starting server')
    print('Waiting for connection...')
    chat_server()


if __name__ == "__main__":
    main()
