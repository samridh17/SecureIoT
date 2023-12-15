from cryptoutils import encrypt_message, decrypt_message, generate_keys, hash_message, check_hash

EXAMPLE_MESSAGE="Hello from client!"
private_key, public_key = generate_keys()

def trudy(encrypted_message, public_key):
    try:
        decrypted_message = decrypt_message(encrypted_message, public_key)
        return decrypted_message
    except Exception as e:
        print("Error:", e)
        return None


if __name__ == "__main__":
    encrypted_message = encrypt_message(EXAMPLE_MESSAGE, public_key)
   
    print("Encrypted message:", encrypted_message)
    print("Public key:", public_key.exportKey().decode())

    decrypted_message = trudy(encrypted_message, public_key)
    print("Decrypted message:", decrypted_message)