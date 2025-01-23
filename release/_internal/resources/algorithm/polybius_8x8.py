import string

symbols = string.ascii_letters + ' ,.!?;:-()\'\"'
step = int(len(symbols) ** .5)
 
if len(symbols) > step * step:
    step += 1
 
n = step * step - len(symbols)
if n > 0:
    symbols += "-" * n
matrix = [symbols[i:i+step].ljust(step, "-") for i in range(0, len(symbols), step)]
last = len(matrix) - 1
 
 
def encode(text):
    for i in text:
        if i not in symbols:
            text = text.replace(i, '∫')
    text = text.replace('∫', '')

    result = []
    for ch in text:
        for i, line in enumerate(matrix):
            if ch in line:
                j = line.index(ch)
                i = 0 if i == last or matrix[i + 1][j] == "-" else i + 1
                result.append(matrix[i][j])
                break
    return "".join(result)
 
 
def decode(text):
    for i in text:
        if i not in symbols:
            text = text.replace(i, '∫')
    text = text.replace('∫', '')

    result = []
    for ch in text:
        for i, line in enumerate(matrix):
            if ch in line:
                j = line.index(ch)
                i = last if i == 0 else i - 1
                ch = matrix[i][j]
                result.append(matrix[i - 1][j] if ch == "-" else ch)
                break
    return "".join(result)