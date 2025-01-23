# Словари для кодирования и декодирования
morse_code = {'a': '.-', 'b': '-...', 'c': '-.-.',
    'd': '-..', 'e': '.', 'f': '..-.',
    'g': '--.', 'h': '....', 'i': '..',
    'j': '.---', 'k': '-.-', 'l': '.-..',
    'm': '--', 'n': '-.', 'o': '---',
    'p': '.--.', 'q': '--.-', 'r': '.-.',
    's': '...', 't': '-', 'u': '..-',
    'v': '...-', 'w': '.--', 'x': '-..-',
    'y': '-.--', 'z': '--..',
    '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..',
    '9': '----.'}

reverse_morse_code = {value: key for key, value in morse_code.items()}


def encode(message):
    """
    Функция для шифрования сообщения в азбуку Морзе.
    :param message: Сообщение на английском языке или цифры.
    :return: Зашифрованное сообщение в азбуке Морзе.
    """
    encoded_message = []
    for char in message.lower():
        if char in morse_code:
            encoded_message.append(morse_code[char] + ' ')
        elif len(encoded_message) > 0:
            if encoded_message[len(encoded_message) - 1] != '/ ':
                encoded_message.append('/ ')
    if encoded_message[len(encoded_message) - 1] == '/ ':
        encoded_message.pop(len(encoded_message) - 1)
    return ''.join(encoded_message).strip()


def decode(morse_message):
    """
    Функция для дешифрования сообщения из азбуки Морзе.
    :param morse_message: Сообщение в азбуке Морзе.
    :return: Расшифрованное сообщение на английском языке или цифры.
    """
    decoded_message = []
    morse_words = morse_message.split('/ ')
    for morse_word in morse_words:
        decoded_word = []
        for morse_char in morse_word.split(' '):
            if morse_char in reverse_morse_code:
                decoded_word.append(reverse_morse_code[morse_char])
        decoded_message.append(''.join(decoded_word))
    return ' '.join(decoded_message)