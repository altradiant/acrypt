import base64

encdng = 'utf-16-le'

def encrypt(plaintext, key):
    key = key.encode(encdng)
    plaintext = plaintext.encode(encdng)
    """Шифрует сообщение с помощью шифра Вернама."""
    if len(plaintext) != len(key):
        raise ValueError("Длина ключа должна быть равна длине сообщения.")
    return base64.encodebytes(bytes([p ^ k for p, k in zip(plaintext, key)])).decode('utf-8').strip()

def decrypt(ciphertext, key):
    """Расшифровывает сообщение с помощью шифра Вернама."""
    key = key.encode(encdng)
    ciphertext = base64.decodebytes(ciphertext.encode('utf-8'))
    if len(ciphertext) != len(key):
        raise ValueError("Длина ключа должна быть равна длине зашифрованного сообщения.")
    return bytes([c ^ k for c, k in zip(ciphertext, key)]).decode(encdng).strip()

# # Пример использования
# if __name__ == "__main__":
#     plaintext = "цацуауц"
#     key = "уцауцаа"
#     rah = vernam_encrypt(plaintext, key)
#     print(rah)
#     unrah = vernam_decrypt(rah, key)
#     print(unrah)
