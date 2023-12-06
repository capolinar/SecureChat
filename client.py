import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

# Client configuration
HOST = '127.0.0.1'  # Loopback address
PORT = 65432


#AES Encryption
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
#decryption
def decrypt_message(key, encrypted_message):
    try:
        encrypted_data = b64decode(encrypted_message)
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode()

    except ValueError as e:
        #print(f"[ERROR] Incorrect padding: {str(e)}")
        print(f"Errors: ")
        return None

#AES Key import
def import_key_from_file(AES_KEY):
    with open(AES_KEY, "rb") as key_file:
        return key_file.read()
    

key = import_key_from_file("AES_KEY")



# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

nickname = input("Please enter nickname: ")


# Function to send messages
def send_message():
    while True:
        message = f'{input()}'
        encrypted_message = encrypt_message(key, message)
        client_socket.send(encrypted_message.encode('utf-8'))


# Function to receive messages
def receive_message():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message == 'GET_NICKNAME':
                client_socket.send(nickname.encode())
            else:
                decrypted_message = decrypt_message(key, message)
                print(decrypted_message)
        except Exception as e:
            # Handle any exceptions (e.g., server disconnects unexpectedly)
            print(f"[ERROR] {str(e)}")
            break


# Start threads for sending and receiving messages
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)


send_thread.start()
receive_thread.start()