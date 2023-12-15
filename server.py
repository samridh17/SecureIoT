# Server Code in Python3

import socket
import threading
import hashlib
from cryptoutils import generate_keys, decrypt_message, encrypt_message, check_hash, hash_message  # Assuming 'utils' is the provided library
from Crypto.PublicKey import RSA
import json

chunk_size = 512

break_integrity = False

# Server class
class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_keys()

        print("-----------------------------------")
        print("GENERATING KEYS")
        print(f"Public key: {self.public_key.exportKey().decode()}")
        print(f"Private key: {self.private_key.exportKey().decode()}")
        print("GENERATED KEYS")
        print("-----------------------------------")

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, address = self.server_socket.accept()
            print(f"Connection from {address} has been established.")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def handle_client(self, client_socket):
        try:
            print("-----------------------------------")
            print("HANDLING CLIENT")
            print(f"Client socket: {client_socket}")
            # Receive client's public key
            client_public_key = RSA.importKey(client_socket.recv(1024))
            
            print(f"Client public key: {client_public_key.exportKey().decode()}")
            print("-----------------------------------")
            # Send server's public key

            print("SENDING PUBLIC KEY")
            print(f"Server public key: {self.public_key.exportKey().decode()}")
            print("-----------------------------------")
            client_socket.send(self.public_key.exportKey())

            # Receive encrypted message from client
            encrypted_message = client_socket.recv(1024)
            print(f"Received encrypted message: {encrypted_message}")

            # Decrypt message
            message = decrypt_message(encrypted_message, self.private_key)

            message = json.loads(message)
            message_text = message["message"]
            message_hash = message["hash"]

            # Check message integrity
            if not check_hash(message_text, message_hash):
                print(f"Message integrity compromised. Message: {message_text}, Hash: {message_hash}")
                raise Exception("Message integrity compromised.")

            print(f"Received message from client: {message_text}")

            print("-----------------------------------")
            print("SENDING RESPONSE")
            # Send response to client
            response = "Hello from server!"
            response_hash = hash_message(response)

            response = {
                "message": response,
                "hash": response_hash
            }

            if break_integrity:
                response["message"] = "Hello from hacker!"

            response = json.dumps(response)
            print(f"Sending response to client: {response}")
            encrypted_response = encrypt_message(response, client_public_key)
            client_socket.send(encrypted_response)

            print(f"Sent encrypted response to client: {encrypted_response}")
            print("-----------------------------------")

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            client_socket.close()

# Starting the server
if __name__ == "__main__":
    server = Server('127.0.0.1', 65431)
    server.start()

