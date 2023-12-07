import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

# Client configuration
HOST = '127.0.0.1'  # Loopback address
PORT = 65432

RUNNERS_GRAY = '#1E1F22'
BG_GRAY = '#414449'
PURPLE = '#6c25be'
WHITE = "white"
FONT = ("Arial", 17)
BUTTON_FONT = ("Arial", 15)
SMALL_FONT = ("Arial", 13)

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

def connect():
    client_socket.connect((HOST, PORT))
    append_message("[SERVER] Successfully connected to the server")
    nickname = nickname_textbox.get()
    client_socket.sendall(nickname.encode())
    
    # Start threads for sending and receiving messages
    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)
    send_thread.start()
    receive_thread.start()
    
    # Start threads for sending and receiving messages
    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)


    send_thread.start()
    receive_thread.start()
    
    nickname_textbox.config(state=tk.DISABLED)
    nickname_button.config(state=tk.DISABLED)

def append_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)


# Function to send messages
def send_message():
    message = message_textbox.get()
    encrypted_message = encrypt_message(key, message)
    client_socket.sendall(encrypted_message.encode('utf-8'))
    message_textbox.delete(0, len(message))

#tkinter gui
root = tk.Tk()
root.geometry("800x600")
root.title("Secure Chat Application")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=800, height=75, bg=RUNNERS_GRAY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=800, height=450, bg=BG_GRAY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=800, height=105, bg=RUNNERS_GRAY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

nickname_label = tk.Label(top_frame, text="Enter nickname:", font=FONT, bg=RUNNERS_GRAY, fg=WHITE)
nickname_label.pack(side=tk.LEFT, padx=10, pady=10)

nickname_textbox = tk.Entry(top_frame, font=FONT, bg=BG_GRAY, fg=WHITE, width=40)
nickname_textbox.pack(side=tk.LEFT)

nickname_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=PURPLE, fg=WHITE, command=connect)
nickname_button.pack(side=tk.LEFT, padx=15, pady=10)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=BG_GRAY, fg=WHITE, width=53)
message_textbox.pack(side=tk.LEFT, padx=10, pady=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=PURPLE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10, pady=10)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=BG_GRAY, fg=WHITE, width=100, height=30)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)

# Function to receive messages
def receive_message():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message == 'GET_NICKNAME':
                print("Nickname =" + nickname_textbox.get())
            else:
                decrypted_message = decrypt_message(key, message)
                append_message(decrypted_message)

        except Exception as e:
            # Handle any exceptions (e.g., server disconnects unexpectedly)
            print(f"[ERROR] {str(e)}")
            break

root.mainloop()