import base64
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class aesInstance:
    def __init__(self, fixedAESMode):
        self.fixedKeyLength = fixedAESMode // 8

    def encrypt_binary(self, data: bytes, password: str) -> bytes:
        plain = data

        padding_length = 16 - len(plain) % 16
        padding = b"\0" * padding_length

        padded_plain = plain + padding

        key = hashlib.sha256(password.encode("utf-8")).digest()[:self.fixedKeyLength]

        iv = get_random_bytes(16)

        aes = AES.new(key, AES.MODE_CBC, iv)

        cipher = aes.encrypt(padded_plain)

        encrypted_data = iv + padding_length.to_bytes(length=1) + cipher

        return encrypted_data


    def decrypt_binary(self, encrypted_data, password):
        iv = encrypted_data[:16]

        padding_length = int.from_bytes(encrypted_data[16:17])

        cipher = encrypted_data[17:]

        key = hashlib.sha256(password.encode("utf-8")).digest()[:self.fixedKeyLength]

        aes = AES.new(key, AES.MODE_CBC, iv)

        padded_plain = aes.decrypt(cipher)

        plain = padded_plain[:-padding_length]

        return plain


    def encrypt_string(self, data: str, password: str) -> str:
        encrypted_data = self.encrypt_binary(data.encode("utf-8"), password)
        return base64.b64encode(encrypted_data).decode("utf-8")


    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        decrypted_data = self.decrypt_binary(base64.b64decode(encrypted_data), password)
        return decrypted_data.decode("utf-8")


# # Example usage

# binary_data = b"hello, world!"
# string_data = "hello, world!"
# password = "123456"

# # Binary data

# print("data (binary):", binary_data)

# encrypted_data = encrypt_binary(binary_data, password)
# print("encrypted_data (binary):", encrypted_data)

# decrypted_data = decrypt_binary(encrypted_data, password)
# print("decrypted_data (binary):", decrypted_data)

# assert binary_data == decrypted_data

# # String data

# print("data (string):", string_data)

# encrypted_data = encrypt_string(string_data, password)
# print("encrypted_data (string):", encrypted_data)

# decrypted_data = decrypt_string(encrypted_data, password)
# print("decrypted_data (string):", decrypted_data)

# assert string_data == decrypted_data