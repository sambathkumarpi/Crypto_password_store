from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import os

def hash_to_group_element(integer):
    """Hashes an integer to an element of the cyclic group"""
    # Use SHA256 as the hash function
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(integer.to_bytes(32, byteorder='big'))  # Assuming 32 bytes for SHA256 output
    hashed_integer = int.from_bytes(digest.finalize(), byteorder='big')
    # Convert the hashed integer to an element of the cyclic group
    return hashed_integer % q  # q is the prime order of the cyclic group

def oprf_client_side(password, r):
    """Client side of the OPRF protocol"""
    # Compute H(P)
    client_input = hash_to_group_element(password)
    # Compute C = H(P)^r
    C = pow(client_input, r, q)  # Modulo exponentiation
    return C

def oprf_server_side(C, s):
    """Server side of the OPRF protocol"""
    # Compute R = C^s
    R = pow(C, s, q)  # Modulo exponentiation
    return R

def compute_z(r):
    """Compute the inverse of r modulo q"""
    z = pow(r, -1, q)  # Modulo inverse
    return z

def derive_secret_key(R, z):
    """Derive the secret key K"""
    K = pow(R, z, q)  # Modulo exponentiation
    return K

# Parameters
q = dh.DHParameterNumbers._RFC3526_PRIME_2048
s = os.urandom(16)  # Generate a random salt
password = b'password'  # Example password

# Client side
r = int.from_bytes(os.urandom(32), byteorder='big')  # Generate a random scalar r
C = oprf_client_side(password, r)

# Server side
R = oprf_server_side(C, int.from_bytes(s, byteorder='big'))

# Client side
z = compute_z(r)
K = derive_secret_key(R, z)

print("Derived secret key:", K)