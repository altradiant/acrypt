import base64
encdng = 'utf-16-le'

def generate_gamma(key, length):
    """Генерирует гамму заданной длины на основе ключа."""
    gamma = []
    for i in range(length):
        # Простая реализация: используем XOR с индексом
        gamma.append(key[i % len(key)] ^ i)
    return bytes(gamma)

def xor_bytes(a, b):
    """Выполняет побайтовое XOR между двумя массивами байтов."""
    return bytes([x ^ y for x, y in zip(a, b)])

def encrypt(plaintext, key):
    """Шифрует сообщение с использованием гаммирования."""
    # Генерируем гамму той же длины, что и сообщение
    plaintext = plaintext.encode(encdng)
    key = key.encode(encdng)

    gamma = generate_gamma(key, len(plaintext))
    # Применяем XOR между сообщением и гаммой
    ciphertext = xor_bytes(plaintext, gamma)
    ciphertext = base64.encodebytes(ciphertext).decode('utf-8')
    return ciphertext.strip()

def decrypt(ciphertext, key):
    """Расшифровывает сообщение с использованием гаммирования."""
    # Генерируем гамму той же длины, что и зашифрованное сообщение
    ciphertext = base64.decodebytes(ciphertext.encode('utf-8'))
    key = key.encode(encdng)

    gamma = generate_gamma(key, len(ciphertext))
    # Применяем XOR между зашифрованным сообщением и гаммой
    plaintext = xor_bytes(ciphertext, gamma)
    return plaintext.decode(encdng).strip()