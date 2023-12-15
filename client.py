# Client Code in Python3

import socket
import hashlib
from cryptoutils import generate_keys, encrypt_message, decrypt_message, hash_message, check_hash  # Assuming 'utils' is the provided library
from Crypto.PublicKey import RSA
import json

break_integrity = True

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_keys()

        # Log
        print("-----------------------------------")
        print("GENERATING KEYS")
        print(f"Public key: {self.public_key.exportKey().decode()}")
        print(f"Private key: {self.private_key.exportKey().decode()}")
        print("GENERATED KEYS")
        print("-----------------------------------")

    def connect(self):
        print("-----------------------------------")
        print("CONNECTING TO SERVER")
        self.client_socket.connect((self.host, self.port))
        print(f"Connected to server on {self.host}:{self.port}")

        # Send public key to server
        self.client_socket.send(self.public_key.exportKey())
        print("SENT PUBLIC KEY")

        # Receive server's public key
        server_public_key = RSA.importKey(self.client_socket.recv(1024))

        # Send encrypted message to server
        message = "Hello from client!"
        message_hash = hash_message(message)

        message = {
            "message": message,
            "hash": message_hash
        }

        if break_integrity:
            message["message"] = "Hello from client! I'm a hacker!"

        message = json.dumps(message)
        print(f"Sending message to server: {message}")
        
        encrypted_message = encrypt_message(message, server_public_key)
        print(f"Encrypted message: {encrypted_message}")

    
        self.client_socket.send(encrypted_message)
        print("SENT ENCRYPTED MESSAGE")
        print("-----------------------------------")

        # Receive server's response
        print("-----------------------------------")
        print("RECEIVING SERVER RESPONSE")
        response = self.client_socket.recv(1024)
        print(f"Received encrypted response from server: {response}")
        
        # Decrypt message
        decrypted_response = decrypt_message(response, self.private_key)
        decrypted_response = json.loads(decrypted_response)
        decrypted_response_text = decrypted_response["message"]
        decrypted_response_hash = decrypted_response["hash"]

        # Check message integrity
        if not check_hash(decrypted_response_text, decrypted_response_hash):
            print(f"Message integrity compromised. Message: {decrypted_response_text}, Hash: {decrypted_response_hash}")
            raise Exception("Message integrity compromised.")
        

        print(f"Server response: {decrypted_response}")
        print("-----------------------------------")
        
        
    def send_encrypted_message(self, message):
        encrypted_message = encrypt_message(message, self.public_key)
        self.client_socket.send(encrypted_message)

    def receive_decrypted_message(self):
        encrypted_message = self.client_socket.recv(1024)
        return decrypt_message(encrypted_message, self.private_key)

    def close(self):
        self.client_socket.close()

# Create and connect client
if __name__ == "__main__":
    client = Client('127.0.0.1', 65431)
    client.connect()
    client.close()

