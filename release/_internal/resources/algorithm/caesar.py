def encrypt(text, shift):
    shift = int(shift)
    s = ''
    for i in range(0, len(text)):
        n = ord(text[i])

        mn, mx, incr = None, None, None

        if n in range(1040, 1103 + 1):
            incr = 32
            mn = 1040
            mx = 1071
            if n in range(1072, 1103 + 1):
                mn += incr
                mx += incr
        elif n in range(65, 90 + 1):
            incr = 25
            mn = 65
            mx = 90
        elif n in range(97, 122 + 1):
            incr = 25
            mn = 97
            mx = 122
        else:
            s += text[i]
            continue

        n += shift
        while n > mx:
            n -= incr
        while n < mn:
            n += incr

        s += chr(n)
    return s


def decrypt(text, shift):
    shift = int(shift)
    return encrypt(text, -shift)