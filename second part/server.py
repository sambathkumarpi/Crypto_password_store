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

def compute_oprf_response(C, s):
    # Here you would replace this function with your actual OPRF response computation
    # For demonstration purposes, we're using a simple example
    # In real-world scenarios, you would use a secure OPRF construction
    return C * s

def server_side():
    host = '127.0.0.1'
    port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            # Generate server's private and public keys
            server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            server_public_key = server_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Send server's public key to the client
            conn.sendall(server_public_key)
            print("Server: Sending public key to client.")

            # Receive client's public key
            client_public_key_bytes = conn.recv(1024)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=default_backend()
            )

            # Compute shared secret
            shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

            # Derive a symmetric key
            key = derive_key(shared_secret)

            # Receive and decrypt client's OPRF value
            encrypted_oprf = conn.recv(1024)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            decrypted_oprf = aesgcm.decrypt(nonce, encrypted_oprf, None)
            C = pickle.loads(decrypted_oprf)

            # Compute OPRF response
            s = os.urandom(32)  # Random salt
            R = compute_oprf_response(C, s)

            # Encrypt and send R to the client
            ciphertext = aesgcm.encrypt(nonce, pickle.dumps(R), None)
            conn.sendall(ciphertext)
            print("Server: Sending encrypted OPRF response to client.")

if __name__ == "__main__":
    server_side()
