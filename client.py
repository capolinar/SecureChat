import socket
import threading


# Client configuration
HOST = '127.0.0.1'  # Loopback address
PORT = 65432


# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))


# Function to send messages

def send_message():
    while True:
        message = input("You: ")
        client_socket.send(message.encode('utf-8'))


# Function to receive messages
def receive_message():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
        except Exception as e:
            # Handle any exceptions (e.g., server disconnects unexpectedly)
            print(f"[ERROR] {str(e)}")
            break


# Start threads for sending and receiving messages
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)


send_thread.start()
receive_thread.start()
print("Please enter your name: ")