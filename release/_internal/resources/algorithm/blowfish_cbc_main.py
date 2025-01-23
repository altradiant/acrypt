import base64
import hashlib

from Cryptodome.Cipher import Blowfish
from Cryptodome.Random import get_random_bytes


class blowfishInstance:
    def encrypt_binary(self, data: bytes, password: str) -> bytes:
        plain = data

        padding_length = 8 - len(plain) % 8
        padding = b"\0" * padding_length

        padded_plain = plain + padding

        key = hashlib.sha512(password.encode("utf-8")).digest()[:56]

        iv = get_random_bytes(8)

        aes = Blowfish.new(key, Blowfish.MODE_CBC, iv)

        cipher = aes.encrypt(padded_plain)

        encrypted_data = iv + padding_length.to_bytes(length=1) + cipher

        return encrypted_data


    def decrypt_binary(self, encrypted_data, password):
        iv = encrypted_data[:8]

        padding_length = int.from_bytes(encrypted_data[8:9])

        cipher = encrypted_data[9:]

        key = hashlib.sha512(password.encode("utf-8")).digest()[:56]

        aes = Blowfish.new(key, Blowfish.MODE_CBC, iv)

        padded_plain = aes.decrypt(cipher)

        plain = padded_plain[:-padding_length]

        return plain


    def encrypt_string(self, data: str, password: str) -> str:
        encrypted_data = self.encrypt_binary(data.encode("utf-8"), password)
        return base64.b64encode(encrypted_data).decode("utf-8")


    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        decrypted_data = self.decrypt_binary(base64.b64decode(encrypted_data), password)
        return decrypted_data.decode("utf-8")