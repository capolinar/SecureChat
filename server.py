import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

HOST = '127.0.0.1'
PORT = 65432

CLIENT_LIST = []
NICKNAMES = []
#AES Encryption/Decryption
def encrypt_message(key, message):
    iv = b'\x00' * 16  

    if isinstance(message, str):
        message_bytes = message.encode()
    elif isinstance(message, bytes):
        message_bytes = message
    else:
        raise TypeError("message must be a string or bytes-like object")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    result = iv + cipher_text
    return b64encode(result).decode()


def decrypt_message(key, encrypted_message):
    encrypted_data = b64decode(encrypted_message)
    iv = encrypted_data[:16]
    cipher_text = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()
#AES Key import
def import_key_from_file(AES_KEY):
    with open(AES_KEY, "rb") as key_file:
        return key_file.read()
   
AES_KEY = import_key_from_file("AES_KEY")




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
            encrypted_message = encrypt_message(AES_KEY, message)
            client.send(encrypted_message.encode('utf-8'))

    def handle(conn, nickname):
        while True:
            try:
                encrypted_message = conn.recv(1024).decode('utf-8')
                if not encrypted_message:
                    break  
                message = decrypt_message(AES_KEY, encrypted_message)
                broadcast(f'{nickname}: {message}')
            except:
                index = CLIENT_LIST.index(conn)
                CLIENT_LIST.remove(conn)
                conn.close()
                print(f'{NICKNAMES[index]} has left the chat')
                NICKNAMES.pop(index)
                break

    while True:
        conn, address = server_socket.accept()
        print(f'Connected with user at address {address}')

        conn.send(f'GET_NICKNAME'.encode())
        nickname = conn.recv(1024).decode()
        CLIENT_LIST.append(conn)
        NICKNAMES.append(nickname)
        print(f'Nickname of user is "{nickname}"')
        conn.send(f'You have successfully connected to the server!\n'.encode())
        broadcast(f'{nickname} has joined the chat!'.encode())

        thread = threading.Thread(target=handle, args=(conn,nickname))
        thread.start()





def main():
    print('Starting server')
    print('Waiting for connection...')
    chat_server()


if __name__ == "__main__":
    main()
