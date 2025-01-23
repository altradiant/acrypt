import hashlib

from Cryptodome.Cipher import Blowfish
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Counter

import base64

encdng = 'utf-8'

class blowfishInstance:
    def encrypt_binary(self, data: bytes, password: str) -> bytes:
        plain = data

        # Derive the key from the password using SHA-256 and truncate it to the desired length
        key = hashlib.sha512(password.encode(encdng)).digest()[:56]

        nonce = get_random_bytes(4)
        ctr = Counter.new(32, prefix=nonce, initial_value=0)

        # Create a Blowfish cipher in CTR mode
        blowfish = Blowfish.new(key, Blowfish.MODE_CTR, counter=ctr)

        # Encrypt the plaintext
        cipher = blowfish.encrypt(plain)

        # Combine the nonce and ciphertext
        encrypted_data = nonce + cipher

        return encrypted_data

    def decrypt_binary(self, encrypted_data: bytes, password: str) -> bytes:
        # Extract the nonce and ciphertext
        nonce = encrypted_data[:4]
        cipher = encrypted_data[4:]

        # Derive the key from the password using SHA-256 and truncate it to the desired length
        key = hashlib.sha512(password.encode(encdng)).digest()[:56]

        # Create a counter with the extracted nonce
        ctr = Counter.new(32, prefix=nonce, initial_value=0)

        # Create a Blowfish cipher in CTR mode
        blowfish = Blowfish.new(key, Blowfish.MODE_CTR, counter=ctr)

        # Decrypt the ciphertext
        plain = blowfish.decrypt(cipher)

        return plain

    def encrypt_string(self, data: str, password: str) -> str:
        # Encrypt the string and encode it in Base64
        encrypted_data = self.encrypt_binary(data.encode(encdng), password)
        return base64.encodebytes(encrypted_data).decode("utf-8")

    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        # Decode the Base64 string and decrypt it
        decrypted_data = self.decrypt_binary(base64.decodebytes(encrypted_data.encode("utf-8")), password)
        return decrypted_data.decode(encdng)