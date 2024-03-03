from cryptography.fernet import Fernet

# Function to generate a random encryption key
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a message
def encrypt_message(key, message):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Function to decrypt a message
def decrypt_message(key, encrypted_message):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message
