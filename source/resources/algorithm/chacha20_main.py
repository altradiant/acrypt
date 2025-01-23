import base64
import hashlib

from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes

nonce_length = 24


class ChaCha20Instance:
    def encrypt_binary(self, data: bytes, password: str) -> bytes:
        key = hashlib.sha256(password.encode("utf-8")).digest()

        nonce = get_random_bytes(nonce_length)

        chacha20 = ChaCha20.new(key=key, nonce=nonce)

        cipher = chacha20.encrypt(data)

        encrypted_data = nonce + cipher

        return encrypted_data


    def decrypt_binary(self, encrypted_data, password):
        nonce = encrypted_data[:nonce_length]

        cipher = encrypted_data[nonce_length:]

        key = hashlib.sha256(password.encode("utf-8")).digest()

        chacha20 = ChaCha20.new(key=key, nonce=nonce)

        plain = chacha20.decrypt(cipher)

        return plain


    def encrypt_string(self, data: str, password: str) -> str:
        print(data.encode("utf-8"))
        encrypted_data = self.encrypt_binary(data.encode("utf-8"), password)
        return base64.b64encode(encrypted_data).decode("utf-8")


    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        decrypted_data = self.decrypt_binary(base64.b64decode(encrypted_data), password)
        # print(encrypted_data, password)
        # print(decrypted_data)
        return decrypted_data.decode("utf-8")
    
# test = ChaCha20Instance()
# enc = test.encrypt_string('helloworld!', 'key')
# print(enc)
# dec = test.decrypt_string(enc, 'key')
# print(dec)