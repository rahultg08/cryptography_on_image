from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

# Encryption function
def encrypt(imagename, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    with open(imagename, 'rb') as file:
        plaintext = file.read()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the encrypted image or do something with the ciphertext

# Decryption function
def decrypt(ciphername, password):
    key = hashlib.sha256(password.encode()).digest()

    with open(ciphername, 'rb') as file:
        ciphertext = file.read()

    iv = ciphertext[:16]  # Extract the IV from the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Save the decrypted image or do something with the plaintext

# Example usage
password = "12345"
image_path = "Images\Image1.jpeg"
cipher_path = "path/to/ciphertext.bin"

encrypt(image_path, password)
decrypt(cipher_path, password)
