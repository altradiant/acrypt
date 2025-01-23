import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Counter

import base64

encdng = 'utf-8'

class aesInstance:
    def __init__(self, fixedAESMode):
        self.fixedKeyLength = fixedAESMode // 8

    def encrypt_binary(self, data: bytes, password: str) -> bytes:
        plain = data

        key = hashlib.sha256(password.encode(encdng)).digest()[:self.fixedKeyLength]

        nonce = get_random_bytes(8)
        ctr = Counter.new(64, prefix=nonce, initial_value=0)

        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        cipher = aes.encrypt(plain)

        encrypted_data = nonce + cipher

        return encrypted_data


    def decrypt_binary(self, encrypted_data, password):
        nonce = encrypted_data[:8]

        cipher = encrypted_data[8:]

        key = hashlib.sha256(password.encode(encdng)).digest()[:self.fixedKeyLength]

        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        plain = aes.decrypt(cipher)

        return plain


    def encrypt_string(self, data: str, password: str) -> str:
        encrypted_data = self.encrypt_binary(data.encode(encdng), password)
        return base64.encodebytes(encrypted_data).decode("utf-8")


    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        decrypted_data = self.decrypt_binary(base64.decodebytes(encrypted_data.encode("utf-8")), password)
        return decrypted_data.decode(encdng)