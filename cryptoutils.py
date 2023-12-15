import base64
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

chunk_size = 256

## Generate public and private keys
def generate_keys():
    modulus_length = 2048 # use larger value in production
    privatekey = RSA.generate(modulus_length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey

## Encrypt message using public key
# @param plain_message: bytes
# @param publickey: RSA key object
# @return base64 encoded encrypted message
## Encrypt message using public key
# @param plain_message: string
# @param publickey: RSA key object
# @return base64 encoded encrypted message
def encrypt_message(a_message, publickey):
    # Encode the string message to bytes
    a_message_bytes = a_message.encode()

    encryptor = PKCS1_OAEP.new(publickey)
    message_chunks = []
    for i in range(0, len(a_message_bytes), chunk_size):
        chunk = a_message_bytes[i:i+chunk_size]
        message_chunks.append(chunk)

    encrypted_chunks = []
    for chunk in message_chunks:
        encrypted_chunks.append(encryptor.encrypt(chunk))

    encrypted_msg = b"".join(encrypted_chunks)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

## Decrypt message using private key
# @param encoded_encrypted_msg: base64 encoded bytes
# @param privatekey: RSA key object
# @return decrypted message
def decrypt_message(encoded_encrypted_msg, privatekey):
    decryptor = PKCS1_OAEP.new(privatekey)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)

    decrypted_chunks = []
    for i in range(0, len(decoded_encrypted_msg), chunk_size):
        chunk = decoded_encrypted_msg[i:i+chunk_size]
        decrypted_chunks.append(decryptor.decrypt(chunk))

    decrypted_msg = b"".join(decrypted_chunks)
    return decrypted_msg.decode()


def hash_message(message):
    return SHA256.new(message.encode()).hexdigest()

def check_hash(message, message_hash):
    return hash_message(message) == message_hash

## Test
def main():
    privatekey, publickey = generate_keys()
    
    # Encryption/Decryption - Confidentiality
    encrypted_msg = encrypt_message("Hello World!", publickey)
    print("Encrypted:", encrypted_msg)

    decrypted_msg = decrypt_message(encrypted_msg, privatekey)
    print("Decrypted:", decrypted_msg)

    # Hashing - Integrity
    hashed_msg = hash_message("Hello World!")
    print("Hashed:", hashed_msg)
    

    # Signing/Verifying - Authenticity
    # signature = sign_message("Hello World!", privatekey)
    # print("Signature:", signature)

    # verified = verify_sign("Hello World!", signature, publickey)
    # print("Verified:", verified)

if __name__ == '__main__':
    main()
