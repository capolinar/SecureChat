from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        # Generate a random IV (Initialization Vector)
        iv = b'\x00' * 16  # You should use a secure random generator for a real implementation

        # Pad the message to make its length a multiple of the block size (128 bits for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        # Create an AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())

        # Encrypt the padded message
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()

        # Combine the IV and cipher text for transmission
        result = iv + cipher_text
        print("Encr")
        return b64encode(result).decode()

    def decrypt(self, encrypted_message):
        # Decode the base64-encoded input
        encrypted_data = b64decode(encrypted_message)

        # Extract the IV and cipher text
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]

        # Create an AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())

        # Decrypt the cipher text
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode()

# Example usage
key = b'Sixteen byte key'
aes_cipher = AESCipher(key)

# Encrypt a message
message_to_encrypt = "This is a secret message!"
encrypted_message = aes_cipher.encrypt(message_to_encrypt)
print(f"Encrypted message: {encrypted_message}")

# Decrypt the message
decrypted_message = aes_cipher.decrypt(encrypted_message)
print(f"Decrypted message: {decrypted_message}")

def export_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def import_key_from_file(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Example usage
keyx = b'Sixteen byte key'

# Export the key to a file
export_key_to_file(keyx, "AES_KEY")

# Import the key from a file
imported_key = import_key_from_file("AES_KEY")

# Ensure the imported key matches the original key
if key == imported_key:
    print("Key import successful")
else:
    print("Key import failed")