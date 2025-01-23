import base64

def xor_encrypt(s, t) -> bytes:
    s = s.encode('utf-8')
    t = t.encode('utf-8')
    while len(t) < len(s):
        t += t
    t = t[:len(t)]

    return base64.encodebytes( bytes(a ^ b for a, b in zip(s, t)) ).decode('utf-8').strip()
    
def xor_decrypt(s, t) -> bytes:
    s = base64.decodebytes( s.encode('utf-8') )
    t = t.encode('utf-8')
    while len(t) < len(s):
        t += t
    t = t[:len(t)]

    return bytes([a ^ b for a, b in zip(s, t)]).decode('utf-8').strip()