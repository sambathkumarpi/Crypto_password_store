import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os

def derive_key(shared_secret):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

def compute_oprf(P, r):
    # Here you would replace this function with your actual OPRF implementation
    # For demonstration purposes, we're using a simple example
    # In real-world scenarios, you would use a secure OPRF construction
    return P * r

def client_side():
    # Establish connection to server
    host = '127.0.0.1'
    port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Generate client's private and public keys
        client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        client_public_key = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Send client's public key to the server
        s.sendall(client_public_key)
        print("Client: Sending public key to server.")

        # Receive server's public key
        server_public_key_bytes = s.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )

        # Compute shared secret
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

        # Derive a symmetric key
        key = derive_key(shared_secret)

        # Compute OPRF
        P = b'ThePassword'  # Example password
        r = os.urandom(32)  # Random scalar
        C = compute_oprf(P, r)

        # Encrypt and send C to the server
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, pickle.dumps(C), None)
        s.sendall(ciphertext)
        print("Client: Sending encrypted OPRF result to server.")

        # Receive and decrypt the server's response
        encrypted_response = s.recv(1024)
        decrypted_response = aesgcm.decrypt(nonce, encrypted_response, None)
        
        print("Client received:", decrypted_response.decode())

if __name__ == "__main__":
    client_side()
