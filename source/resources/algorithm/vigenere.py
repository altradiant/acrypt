alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯabcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя .,:;'\"()-=+!?"

def encrypt(plaintext: str, key: str) -> str:
    global alphabet
    ciphertext = ""
    
    key = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]
    
    for i in range(len(plaintext)):
        plaintext_char = plaintext[i]
        key_char = key[i]
        
        plaintext_index = ''
        try:
            plaintext_index = alphabet.index(plaintext_char)
        except:
            raise ValueError(f'Возможные символы: {alphabet}')
        key_index = alphabet.index(key_char)
        
        ciphertext_index = (plaintext_index + key_index) % len(alphabet)
        
        ciphertext += alphabet[ciphertext_index]
    
    return ciphertext


def decrypt(ciphertext: str, key: str) -> str:
    global alphabet
    plaintext = ""
    
    key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    
    for i in range(len(ciphertext)):
        ciphertext_char = ciphertext[i]
        key_char = key[i]
        
        ciphertext_index = ''
        try:
            ciphertext_index = alphabet.index(ciphertext_char)
        except:
            raise ValueError(f'Возможные символы: {alphabet}')
        key_index = alphabet.index(key_char)
        
        plaintext_index = (ciphertext_index - key_index) % len(alphabet)
        
        plaintext += alphabet[plaintext_index]
    
    return plaintext