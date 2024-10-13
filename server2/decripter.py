from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# A fixed key for AESGCM; 
# key = AESGCM.generate_key(bit_length=128)
key  = b'*\x9d\x81\x05\\\xb3\xb0<\xea\xb1\x11\xf3\xae\x8a\xd4\x10'

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json.get('password_hash')
    print("data----------->", data)
    if data is None:
        return jsonify({'error': 'No data provided'}), 400

    # Convert data to bytes
    data_bytes = data.encode()

    # Using a fixed nonce for deterministic encryption
    nonce = b'\x04\xeb\xe3\xf0\xa0\xbb_\xd9M\xe9\xeb\x02'  # 12 bytes nonce for AESGCM

    print(nonce)

    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, data_bytes, None)

    # Encoding the encrypted data to base64 to make it JSON-serializable
    encrypted_data_b64 = encrypted_data.hex()

    print(encrypted_data_b64)

    return jsonify({'encrypted_data': encrypted_data_b64})

if __name__ == '__main__':
    app.run(debug=True)
