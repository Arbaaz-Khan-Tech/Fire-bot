from cryptography.fernet import Fernet

# Function to decrypt a message
def decrypt_message(key, encrypted_message):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Function to handle decryption command
def handle_decryption(decryption_key):
    # Read the encrypted message from the file
    with open("encrypted_file.txt", "rb") as f:
        encrypted_message = f.read()

    # Create a Fernet symmetric encryption object with the provided key
    cipher = Fernet(decryption_key.encode())

    # Decrypt the message
    decrypted_message = decrypt_message(decryption_key.encode(), encrypted_message)

    return decrypted_message
