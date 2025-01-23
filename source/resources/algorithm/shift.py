def encrypt(text, shift):
    shift = int(shift)
    result = ''
    for i in text:
        result += chr(ord(i) + shift)
    return result

def decrypt(text, shift):
    shift = int(shift)
    return encrypt(text, -shift)