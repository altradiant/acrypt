# ----- Стандартные импорты -----

import os
import pathlib
import sys
import base64
import traceback

from getpass import getuser

from datetime import datetime

# ----- Импорт простых алгоритмов из файлов -----

from resources.algorithm import caesar, vigenere, rail_fence, polybius_8x8, morse_en, morse_ru, vernam, shift, xor, gamma, rc4

# ----- Импорт сложных алгоритмов из библиотеки Cryptodome

from resources.algorithm import aes_cbc_main
aes256 = aes_cbc_main.aesInstance(256)

from resources.algorithm import aes_ctr_main
aes256_ctr = aes_ctr_main.aesInstance(256)

from resources.algorithm import blowfish_cbc_main
blowfish = blowfish_cbc_main.blowfishInstance()

from resources.algorithm import blowfish_ctr_main
blowfish_ctr = blowfish_ctr_main.blowfishInstance()

from resources.algorithm import chacha20_main
chacha20 = chacha20_main.ChaCha20Instance()

from resources.algorithm import des_cbc_main
des = des_cbc_main.desInstance()

from resources.algorithm import des_ctr_main
des_ctr = des_ctr_main.desInstance()

# ----- Импорт Qt -----

from PySide6 import QtGui, QtWidgets

from PySide6.QtCore import Qt
from PySide6.QtUiTools import QUiLoader

# ----- QDarkStyle -----

import qdarkstyle

# ----- Прочее -----

from resources.py import ru_month

# ----- Глобальные константы -----

# Словарь шифров
# 0 - Функция закодирования
# 1 - Функция декодирования
# 2 - Требует ключ
# 3 - Требует дополнительный параметр
# 4 - Ошибка о нехватке ключа
# 5 - Ошибка о нехватке доп. параметра (если нет дефолта)
# 6 - Дефолт для доп. параметра
ALGORITHM_DICT = {
    'Вернам': [vernam.encrypt, vernam.decrypt, True, False, 'Шифр Вернама требует ключ (строку), длина которой равна длине сообщения.'],
    'Виженер (англ. и рус. с регистром, знаки препинания)': [vigenere.encrypt, vigenere.decrypt, True, False, 'Шифр Виженера требует строковый ключ.'],
    'Гаммирование': [gamma.encrypt, gamma.decrypt, True, False, 'Гаммирование требует ключ (текст).'],
    'Квадрат Полибия (англ. с регистром, знаки препинания)': [polybius_8x8.encode, polybius_8x8.decode, False, False],
    'Морзе (англ., цифры)': [morse_en.encode, morse_en.decode, False, False],
    'Морзе (рус., цифры)': [morse_ru.encode, morse_ru.decode, False, False],
    'Ограждение рельсов': [rail_fence.encrypt, rail_fence.decrypt, True, True, 'Шифр ограждения рельсов требует ключ (количество рельсов).', '', 0],
    'Простой сдвиг': [shift.encrypt, shift.decrypt, True, False, 'Простой сдвиг требует числовой ключ (сдвиг).'],
    'Цезарь': [caesar.encrypt, caesar.decrypt, True, False, 'Шифр Цезаря требует числовой ключ (сдвиг).'],
    'AES-256 (CBC)': [aes256.encrypt_string, aes256.decrypt_string, True, False, 'AES-256 в режиме CBC требует пароль (строку).'],
    'AES-256 (CTR)': [aes256_ctr.encrypt_string, aes256_ctr.decrypt_string, True, False, 'AES-256 в режиме CTR требует пароль (строку).'],
    'Blowfish (CBC)': [blowfish.encrypt_string, blowfish.decrypt_string, True, False, 'Blowfish в режиме CBC требует пароль (строку).'],
    'Blowfish (CTR)': [blowfish_ctr.encrypt_string, blowfish_ctr.decrypt_string, True, False, 'Blowfish в режиме CTR требует пароль (строку).'],
    'base16': [lambda x: base64.b16encode(bytes(x, 'utf-8')).decode('utf-8'), lambda x: base64.b16decode(bytes(x, 'utf-8')).decode('utf-8'), False, False],
    'base32': [lambda x: base64.b32encode(bytes(x, 'utf-8')).decode('utf-8'), lambda x: base64.b32decode(bytes(x, 'utf-8')).decode('utf-8'), False, False],
    'base64': [lambda x: base64.b64encode(bytes(x, 'utf-8')).decode('utf-8'), lambda x: base64.b64decode(bytes(x, 'utf-8')).decode('utf-8'), False, False],
    'ChaCha20 (XChaCha20)': [chacha20.encrypt_string, chacha20.decrypt_string, True, False, 'ChaCha20 требует пароль (строку).'],
    'DES (CBC)': [des.encrypt_string, des.decrypt_string, True, False, 'DES в режиме CBC требует пароль (строку).'],
    'DES (CTR)': [des_ctr.encrypt_string, des_ctr.decrypt_string, True, False, 'DES в режиме CTR требует пароль (строку).'],
    'RC4': [rc4.encrypt, rc4.decrypt, True, False, 'RC4 требует ключ (текст).'],
    'XOR': [xor.xor_encrypt, xor.xor_decrypt, True, False, 'XOR требует ключ (текст).']
    }

# Словарь толщин шрифта (неизменяемый в ближайшее время)
FONT_WEIGHT_DICT = {100: QtGui.QFont.Thin, 200: QtGui.QFont.ExtraLight, 300: QtGui.QFont.Light, 400: QtGui.QFont.Normal, 500: QtGui.QFont.Medium, 600: QtGui.QFont.DemiBold, 700: QtGui.QFont.Bold, 800: QtGui.QFont.ExtraBold, 900: QtGui.QFont.Black}

# 0 - Название уровня
# 1 - Требуемый прогресс
USER_MAX_LEVEL = 3
USER_LEVEL_DICT = {
    0: ['Ознакомительный', 6],
    1: ['Простой', 6],
    2: ['Средний', 9],
    3: ['Продвинутый', 13]
    }

# Словарь заданий
# Ключ - (уровень; прогресс)
# 0 - файл интерфейса окна (заготовка)
    # тип: task_window.ui
    # 1 - текст задания
    # 2 - ответ на задание
    # 3 - важность регистра
TASK_DICT = {
    (0, 0): [
        'task_window.ui',
        '''Заполните пропуск:\n\n*Симметричное шифрование основано на использовании ...... секретного ключа как для шифрования исходных данных, так и для их последующего расшифровывания.*\n\nКоличество точек соответствует количеству букв.''',
        '''одного''',
        False
    ],
    (0, 1): [
        'task_window.ui',
        '''Cопоставьте понятия и определения:\n\n**1** - plaintext\n\n**2** - ciphertext\n\n**3** - secret key\n\n**4** - encryption algorithm\n\n**5** - decryption algorithm\n\n**А** - процедура расшифровывания\n\n**Б** - ключ\n\n**В** - зашифрованный текст\n\n**Г** - открытый текст\n\n**Д** - процедура шифрования\n\nОтвет запишите в следующем формате: 1А-2Б-3В-4Г-5Д (пример).''',
        '''1Г-2В-3Б-4Д-5А''',
        True
    ],
    (0, 2): [
        'task_window.ui',
        '''Вам необходимо отправить зашифрованное азбукой Морзе сообщение на русском языке. Что следует отправить?\n\n//\n\n*Содержание сообщения следующее*:\n\n**встречаемся на востоке в 8**\n\n//\n\nНе забудьте использовать вариацию шифра, соответствующую необходимому языку.''',
        '''.-- ... - .-. . ---. .- . -- ... .-.- / -. .- / .-- --- ... - --- -.- . / .-- / ---..''',
        None
    ],
    (0, 3): [
        'task_window.ui',
        '''На ваше сообщение пришел ответ. Однако вы знаете, что отправитель использует английский язык. Каково содержание ответа?\n\n//\n\n*Содержание сообщения следующее*:\n\n**-.-. .-.. . .- .-. / ..- -. -.. . .-. ... - --- --- -..**\n\n//\n\nНе забудьте использовать вариацию шифра, соответствующую необходимому языку.''',
        '''clear understood''',
        None
    ],
    (0, 4): [
        'task_window.ui',
        '''Вы ведёте переписку, однако вы и другой человек используете шифр Цезаря в качестве простого метода засекречивания информации.\n\nВы знаете, что сдвиг равен 4.\n\n//\n\n*Недавно вам пришло следующее сообщение*: **Г сй лсдв, ыцт ийпдца, ст г утхцдфдвха хтщфдсгца туцмрмлр.**\n\n//\n\nКакое сообщение вы получили?''',
        '''Я не знаю, что делать, но я постараюсь сохранять оптимизм.''',
        True
    ],
    (0, 5): [
        'task_window.ui',
        '''Продолжение предыдущего задания с шифром Цезаря.\n\nСдвиг равен 4.\n\n//\n\n*Вы пишете ответ*: **Это хорошо. Я верю в то, что у тебя всё получится.**\n\n//\n\nКак будет выглядеть зашифрованное сообщение?''',
        '''Бцт щтфтьт. Г жйфв ж цт, ыцт ч цйег жхё утпчымцхг.''',
        True
    ],

    (1, 0): [
        'task_window.ui',
        '''У вас есть сообщение:\n\n**Firestarter in The Woods!**\n\nЧтобы его не прочитали другие, вы и ваша команда используете квадрат Полибия 8x8 со знаками препинания и буквами английского языка с разным регистром.\n\nОднако до этого вам пришло следующее указание, зашифрованное тем же образом:\n\n**Lw(vwB(CAm(Bpm(Ewzl(hNqzmABizBmzh'(Zmxtikm(qB(EqBp(hLivomzwjrmkBh**'\n\nЧто следует отправить команде?''',
        '''LivomzwjrmkB(qv(,pm(?wwlA"''',
        True
    ],
    (1, 1): [
        'task_window.ui',
        '''Дан следующий квадрат Полибия 5x5:\n\n\n\n**ABCDE**\n\n**FGHIJ**\n\n**KLMNO**\n\n**PQRST**\n\n**UVWXY**\n\n\n\nПришло следующее сообщение, зашифрованное обычным методом с вышеуказанным квадратом: **MNYMJWJ**\n\nЧто зашифровано?''',
        '''HITHERE''',
        True
    ],
    (1, 2): [
        'task_window.ui',
        '''Известен следующий шифротекст, полученный с помощью шифра Цезаря:\n\n**чкю (ьпрьз мжце хщэзух)**\n\nКакой ключ (минимально возможный положительный сдвиг) нужно использовать, чтобы расшифровать сообщение?''',
        '''11''',
        False
    ],
    (1, 3): [
        'task_window.ui',
        '''Используя программную реализацию шифра Виженера, зашифруйте фразу\n\n**Привет, мир!**\n\nиспользуя ключ\n\n**Python**\n\nЧто получилось?''',
        '''ЮЪНVЕСDkСВРl''',
        True
    ],
    (1, 4): [
        'task_window.ui',
        '''Пришло следующее сообщение, зашифрованное программной реализацией шифра Виженера:\n\n**ЯRhZхVЩVEOhВцДhЙ;ГХГ**\n\nВы знаете, что используется следующий ключ:\n\n**Save**\n\nКаково содержание сообщения?''',
        '''Не идите в лес утром''',
        True
    ],
    (1, 5): [
        'task_window.ui',
        '''![IMAGE_FILE](/txt/txt_img/custom_vigenere_square.png)\n\nВыше дан квадрат Виженера. Вам известен ключ для секретной переписки:\n\n**DIGGIHELL0**\n\nПришло следующее сообщение:\n\n**A0KMLLIB1H**\n\nЧто пришло?''',
        '''IG0D1000CD''',
        False
    ],
    (2, 0): [
        'task_window.ui',
        '''Представьте, что у вас есть некоторая строка, которая используется в некоей программе:\n\n**VXNlRGV2TW9kZT1GYWxzZQ==**\n\nВы знаете, что в ней содержится булева переменная (True или False). Вам необходимо заменить строку так, чтобы в ней было противоположное значение в конце (если было True, то стало False и наоборот.)\n\nЗапишите, какая должна быть строка.''',
        '''VXNlRGV2TW9kZT1UcnVl''',
        True
    ],
    (2, 1): [
        'task_window.ui',
        '''Что получится, если дважды зашифровать шифром XOR\n\n**Они, что познали смерть.**\n\nпрограммной реализации (используйте ключ: **hi**)? А какое сообщение получится, если зашифровать то же сообщение дважды, *но не использовать base64*?\n\nОтвет запишите следующим образом:\n\n**<ответ на вопрос 1>;<ответ на вопрос 2>**''',
        '''HTkNXVklAjs6LAVcXxsGGx0nDCAdDQ1cWRsGDx0NP1xaJQY9HQ0qIx0MAV1ZCwIKHQwFXF5eBgU6
DlVU;Они, что познали смерть.''',
        True
    ],
    (2, 2): [
        'task_window.ui',
        '''Расшифруйте XOR:\n\n**6IfggOS05Lblg+WD6IrghQ==**\n\nесли известно, что ключ:\n\n**88005553535**''',
        '''пасхалка''',
        True
    ],
    (2, 3): [
        'task_window.ui',
        '''Зашифруйте шифром Вернама следующее сообщение:\n\n**-=-=-_Мостик**\n\nесли ключ равен:\n\n**abi**\n\nПовторяйте ключ до тех пор, пока он не достигнет нужной длины. Безопасно ли, с точки зрения криптографии, это делать?\n\nПредоставьте ответ так:\n\n**<сообщение>;<да/нет>**''',
        '''TABfAEQAXABPADYAfQRcBCgEIwRaBFME;нет''',
        True
    ],
    (2, 4): [
        'task_window.ui',
        '''Пришло зашифрованное шифром Вернама сообщение:\n\n**ZAR/BVkAStyR2V6hewSIBjMEDQRFBaYGti6OBkMunwY7IdQhxwY=**\n\nИзвестно, что ключ:\n\n**vŊЙ𒆩ꕤKʳНЭŵ˧⪎ʲ⩼˝┅▖˷**\n\nОцените ключ, повторяемость символов, его длину, длину сообщения. Будет ли в таком случае шифрование абсолютно безопасным, с точки зрении криптографии, если это первый раз использования ключа?\n\nПредоставьте ответ так:\n\n**<расшиф. сообщение>;<да/нет>**''',
        '''Вертикал. асимптота;да''',
        True
    ],
    (2, 5): [
        'task_window.ui',
        '''Выберите все неверные и верные варианты:\n\nГаммирование отличается от шифра Вернама тем, что ...\n\n**а)** Гамма в гаммировании есть обработанная последовательность байтов, на основе ключа\n\n**б)** Шифр Вернама не может быть абсолютно стойким, с точки зрения криптографии\n\n**в)** Не использует XOR\n\n**г)** Позволяет использовать более простые ключи, не снижая безопасность работы шифра\n\nЗапишите ответ как:\n\n**<неправильные ответы в алфавитном порядке, только маленькие буквы>;<правильные ответы в алфавитном порядке, только маленькие буквы>**\n\n*Пример ответа: ежи;аг*''',
        '''бв;аг''',
        True
    ],
    (2, 6): [
        'task_window.ui',
        '''Пришло зашифрованное гаммированием сообщение:\n\n**WwEMBxUBCQNwCR8Pfg0CCx0RHRMYEWcXCBl3HxgZHR81JVAjUSErJ1gpWy9YLSwrIDU2N0I1IzM9
OTk7MT01OwlBO0dDRVJHS0k6T0FNYU9XVUlXV1VcU19ZU18wWS1bG2FjY3RhYWMHbWZrHWkab3J1
E3cHcQh3dXkIe3t5aHv/gYmH/oWWh+KNg4+GjZiLnpGZl4eRkJeJmembkZmDm9al3KO0oa6npK2n
q+epvq8=**\n\nИзвестен ключ:\n\n**ф0-1ы-а9-г1**\n\nРасшифруйте сообщение и отправьте ответ. Запишите ваш, зашифрованный тем же способом, что и сообщение, ответ в качестве решения задания.''',
        '''fQULAw==''',
        True
    ],
    (2, 7): [
        'task_window.ui',
        '''Сообщение на RC4 выглядит следующим образом:\n\n**CE4DAE3F724CDAAE4383C4CD4C2073FD5228A484BF**\n\nА ключ так:\n\n**qbnWCxlclZnRzA4qJXxtlv9PnbacxgbtHpY=**\n\nЧто в сообщении?''',
        '''Basalt Delta Ambiance''',
        True
    ],
    (2, 8): [
        'task_window.ui',
        '''1: Через какие этапы проходят ключ и S-box в RC4, чтобы стать гаммой? Приведите их сокращённые названия на английском в порядке прохождения.\n\n2: Зашифруйте сообщение\n\n**attack @ dawn**\n\nключом\n\n**ihsamveelvbaorriposu**\n\nи приведите зашифрованное сообщение в качестве ответа.\n\nОтвет приведите следующим образом:\n\n**<первый этап перестановок>;<второй этап перестановок>;<зашифрованное сообщение>**''',
        '''KSA;PRGA;1B3D29EB0359E6A25A04AECC3B''',
        False
    ],
    (3, 0): [
        'task_window.ui',
        '''Заполните пропуски. Количество точек соответствует количеству букв. В ответ запишите слова через пробелы так:\n\n**<слово1> <слово2> <слово3>**\n\n**Блочные шифры обрабатывают данные ....... ............. .....**''',
        '''блоками фиксированной длины''',
        False
    ],
    (3, 1): [
        'task_window.ui',
        '''Назовите 4 основных режима работы блочных шифров (их сокращённые названия на англиском), которые вы знаете, в любом порядке.''',
        lambda x: 'ecb' in x and 'ctr' in x and 'gcm' in x and 'cbc' in x,
        None
    ],
    (3, 2): [
        'task_window.ui',
        '''Заполните пропуски. Количество точек соответствует количеству букв.\n\nШифрование блочным шифром в CBC, на примере DES:\n\n**1:** Создание ключа с помощью ...-функции из заданного текста\n\n**2:** Деление исходных данных на .....\n\n**3:** Создание .., применение его к первому блоку\n\n**4:** Применение алгоритма шифра DES к блокам текста\n\n**5:** Стыковка .. к началу шифротекста\n\n**6:** Кодирование ......\n\nОтвет приведите следующим образом:\n\n**<слово1>;<слово2>;<слово3>;<слово4>;<слово5>**\n\n*Подумайте самостоятельно, как проходит процесс расшифровки.*''',
        '''хэш;блоки;iv;iv;base64''',
        False
    ],
    (3, 3): [
        'task_window.ui',
        '''Заполните пропуски. Количество точек соответствует количеству букв.\n\nРасшифрование блочным шифром в CTR, на примере DES:\n\n**1:** Создание ключа с помощью ...-функции из заданного текста\n\n**2:** Преобразование шифротекста обратно в байты из текста, закодированном ......\n\n**3:** Половина первого блока содержит значение ....., она открепляется\n\n**4:** Создание ........ с префиксом .....\n\n**5:** Применение алгоритма шифра DES к потоку текста\n\nОтвет приведите следующим образом:\n\n**<слово1>;<слово2>;<слово3>;<слово4>;<слово5>**\n\n*Подумайте самостоятельно, как проходит процесс расшифровки.*''',
        lambda x: x in ['''хэш;base64;nonce;счётчика;nonce''','''хэш;base64;nonce;счетчика;nonce'''],
        False
    ],
    (3, 4): [
        'task_window.ui',
        '''Сообщение DES (CBC) выглядит следующим образом:\n\n**w778JRUlYiQBIJJrLinLrdXKK6hmTP5toEu30vnwUiWvnMwMLGfr8YaoOrC53u14V08oi/ikjvEx
Pl4PCL60Fr4Hy5eacI8ZqrQBuUDwkkON5u5/JnTXAzmPOkoLsbwRkEpV8+3HXcw8AWvuN5ACvjKm
mizqhc6ZKOCuFNuujdjd0yhmswL3AscJvBf8O6gYWE7cQXjemkJSj8NUCRIHxtNc9shxOhXhs42v
umTQ3KCng6MV9E33eqM=**\n\nА ключ так:\n\n**G4fYSvdmGzvP7**\n\nПрочитайте сообщение и отправьте ответ на задание.''',
        lambda x: des.decrypt_string(x.strip(), 'G4fYSvdmGzvP7') == '''1991''',
        True
    ],
    (3, 5): [
        'task_window.ui',
        '''Сообщение DES (CTR) выглядит следующим образом:\n\n**E+FS8EQNEevOOaYIaZZ0aCs8stffP9dvtuVTRmQsUt8QsQoA+JZHWJLzQ4WN/jFC9JqCOlY1XkkB
ipSsf6e0CY7qoEHdJ47DQao0xyzg8T2fkbk0Zl7/I4CLFenFdvRIJlQIrrBXoF1r5XEslmFTzQsG
z0igQOdc+SjT1CHiXkNd56X2XFvr2yb3JdjHI3EPb1oC1ZE41gCqXY/JPCLSybl1rzYtoDmA24DM
OYVX6rp835NDJA6uI/pA2jYGmmVVHW+7krwBUVZLUsSP10kTq360RLhE6Is9HcrcN+jvUh2xNbHg
trYTQc5XEeYv6otbjMBWTi7Aj1hwmFHw9xeKPVmAGfDY4TwGp+eTmxH0G+JkMCbQ3mn2mF9sPtk=**\n\nА ключ так:\n\n**ЂЕq$IУ<ПуDС4U•гX–¦yћ(љ¦Єє.З±,Mу<Q4MUu]**\n\nПрочитайте сообщение и отправьте ответ на задание.''',
        lambda x: des_ctr.decrypt_string(x.strip(), '0ILQlXEkSdCjPNCf0YNE0KE0VeKAotCzWOKAk8KmedGbKNGZwqbQhNGULtCXwrEsTdGDPFE0TVV1XQ==') == '''Толстой''',
        True
    ],
    (3, 6): [
        'task_window.ui',
        '''Заполните пропуск тремя цифрами:\n\nВ шифраторе используется AES с ключом длиной ___ бит.''',
        '''256''',
        None
    ],
    (3, 7): [
        'task_window.ui',
        '''Прочитайте сообщение, зашифрованное AES-256 в режиме CBC и ключом\n\n**🜳🜖🝛🝩🝘🝟🝒🜞🜃🜯🝲🝒🝗🜦🝞🜭🜿🜧🝝🜩🝛🜕🜜🝅🝦🜯🜁🜔**\n\nи отправьте соответств. ответ:\n\n**3jmAMReatxZS1ZiPto2DDwM5C4q4WhrwPGiTvxnk3HoKSrJIt5yslwAM5zWrUiN0GiNxH4YbAyh+JeKuwjjg4IwCRPL4umiLTdknW2GLQC2wmzH14AVmA+2yHK7Q1P0IuR3YtEikNGW4Qmv2J+gZ21msmhMFCzT13SwHpJ/nEz+ZGT1zHWNYU/oFv5D9E8JMBOqjxGxN1w3RqkitAOHOuj0fqX5TCxjyWCqqUTPPe2ANxfNXTi1dILfaKYTZmoGINx+vqcWrAG+OUyrBz308PSQQb3C+TBnzSzOp9y+kvXlJLs7gvzOHDmbzN2vtMS9PBlaEu7wGvBe/WCOWDxiVCCyo2RHwfXm0IAyUkhSr2ncBKW0R9BZTj3TqW3nzamAXxiJWLJhIui0bKpHMjBvMQhg=**''',
        lambda x: aes256_ctr.decrypt_string(x.strip(), '▖▚▞▖▗▝') == '11',
        True
    ],
    (3, 8): [
        'task_window.ui',
        '''Прочитайте сообщение, зашифрованное AES-256 в режиме CTR и ключом\n\n**⌀⌝⌰⌙⌟〉⌙⌥⋘⋾⌧〉⋘⌬⌠⌝⋘⋻〉⌝⌙⌬⌡⌮⌝⋘⌀⌝⌙⌮⌝⌦**\n\nи отправьте соответств. ответ:\n\n**0UD+fkgLpf95nF9UoOCLfj1xjrlrg8HqjmnS2V+rTXHs/W/i+oAU+/qyZUnJnlFNDajUORxyL2zs
4LzBcwxVlLGQfbyuRVIXqbHnjdoSZuRb8PjmelpduP6SlsewTr8GtCmurfPN931iX09wVvMjmuJp
7/h0GpPcDVj9caC3LikpqzRT5Rk7jsveU7Am63ccd4iQAyU4ATZ5LB7me1v6gQkytX+msftkHVwE
mGx0SqWwbPr8jsYgxJeOUcNs+AUDIPe6Wq9bFULg1Sas1KTUTkgvTiXkek/Q48c3EWIzYQnncC+Z
Zc5K0oJdfb0wAIAKto3toNscOUHm2Y3kf5eg+xugrusEA8zfnli/IKZ7n+w0A/j9v1m7F9Pz5frZ
/dMRV78qHdRPoA2N1RneNfwrxnsbvqKh4GtMQMtyojyfUTCYv8o7UXhPSL/Doa9y8zakwUxh8Hc0
EbuYjnMXS/9ZVkOY2CfSXXLfu0XL8jrJs6qq81h5uD87JPqqtnpXgOIsswvnyjKBBVDA5CDOwPAi
8f2bnvk7sNJD9Bsb0XfyzHl1J3vgrJDNkslRqP9VsJFnT4n0Dp6RMVc7WSFdmXySbAdnwjxlLaZm
2+9h5Ty5A3O/HuiB6XSgEQwqIcXbX3VoqCJ+Ez7F6XgUKdOyLQ==**''',
        lambda x: aes256.decrypt_string(x.strip(), '6379617572697468') == '°',
        True
    ],
    (3, 9): [
        'task_window.ui',
        '''Текст на Blowfish (CBC):\n\n**JtErw/7ARZMD6D7UgvYcXkm5ox0paHt84I9QOlzDrWdb67GIYIIYSNE=**\n\nКлюч:\n\n**JEILIJsIOYI;JIwMLYY**\n\nЧто зашифровано?''',
        '''иглобрюхая рыба''',
        True
    ],
    (3, 10): [
        'task_window.ui',
        '''Сообщение на Blowfish (CTR) выглядит следующим образом:\n\n**dG1VVpH5EQ2mJoX6TGWePV5KTMiZ2vdjFHX7vbTyFsdwgpYEqpZ+XzQEdj9zR1JWEtDUi5XWyZs6
FzumKZGeRzLMc0gF1Bpv6c6cFbgIjPi23vO0XddZGhf0qHMnXArx53/46FYhBC0Ff+J6G+a5HU7q
2w6mj0b/fj+rKaLeFw==**\n\nКлюч:\n\n**-============хъ**\n\nОтправьте соответств. ответ.''',
        lambda x: blowfish_ctr.decrypt_string(x, '-============хъ') == '01 00 10',
        True
    ],
    (3, 11): [
        'task_window.ui',
        '''В программной реализации используется:\n\n**1:** ChaCha20\n\n**2:** XChaCha20\n\nXChaCha20 отличается тем, что имеет ..-байтный nonce, тем самым повышая безопасность при большом количестве сообщений, учитывая, что nonce непредсказуем и не переиспользован.\n\nПредоставьте ответ как:\n\n**<цифра, обозначающая правильный вариант ответа>;<кол-во байт в nonce>**''',
        '''2;24''',
        None
    ],
    (3, 12): [
        'task_window.ui',
        '''Сообщение на XChaCha20 выглядит следующим образом:\n\n**73zypCM7pcD/2IFRRUuiXE71hdg+2nJPWeujED2hinV1aK0lufwfaG1XXGDNf4GDDKHGbzzwmsZVcdvOvLq7C664CODG53jc1vbIyr/LHRN+ftooGECOKRz50J4ybI+SBYc27Nb/Eqdjh838gv0zEfLpNm7fB1UdwPuNSxdAth8JZhifrbwceml9eGtGz+mXOZBaIklc4I6PoU6ptjPxV87P3oKKg0i7qcPt1r4YNjzsp8fdue5su24rvsU8y+Q=**\n\nКлюч:\n\n**0LzQvtGB0YLQuNC60YPQvDIyOA==**\n\nОтправьте соответств. ответ.''',
        lambda x: chacha20.decrypt_string(x, '-X====>').lower() == ru_month.main(),
        True
    ],
}

thingy = '�￼�'

PROGRESS_SAVE_NAME = 'progress.txt'
SIMULATION_LAST_SAVE_NAME = 'simulation_last.txt'
LIBRARY_FONT_SAVE_NAME = 'library_font.txt'
LIBRARY_LAST_SAVE_NAME = 'library_last.txt'
IS_DARK_THEME_SAVE_NAME = 'is_dark_theme.txt'

IS_DARK_THEME = 0

BACKSLASH = '\\'

# ----- Глобальные переменные -----

currentLevel = 0
currentProgress = 0

secondaryWindows = []

mainWindowShell = None
mainWindow = None
taskWindowShell = None
infoWindow = None

# ----- Глобальные функции -----

# Возвращатель настоящего относительного путя
def rpath(obj):
    return os.fspath(pathlib.Path(__file__).parent / obj)

# Создатель окна с оболочкой
def makeComplexWindow(window, shell):
    newBase = shell()
    orgObject = window()

    org = orgObject.window

    newBase.show()
    org.show()
    newBase.setRealObject(orgObject)

    newBase.setWindowTitle(org.windowTitle())
    newBase.setGeometry(org.geometry())
    newBase.setMaximumSize(org.maximumSize())
    newBase.setMinimumSize(org.minimumSize())
    newBase.setCentralWidget(org)

    return orgObject, newBase

# Быстрый устанавливатель планировки
def setWidgetLayout(window, holderName, layoutName, objectNames):
    layout = getattr(window, layoutName)
    holder = window
    if holderName:
        holder = getattr(window, holderName)
    for i in objectNames:
        layout.addWidget(getattr(window, i))
    holder.setLayout(layout)

# Возвращает безопасную версию функции (можно использовать как декоратор)
def safeFunc(func):
    def inner(*args, **kw):
        try:
            return func(*args, **kw)
        except Exception as e:

            # Где случилась ошибка
            print(f'[!] ERROR @ {datetime.now().strftime("%H:%M:%S")} // Full traceback:')
            traceback.print_tb(e.__traceback__)
    return inner

# Возвращает безопасную версию функции, сообщающую об ошибке (также можно использовать как декоратор)
def safeFuncWAlert(func):
    def inner(*args, **kw):
        try:
            return func(*args, **kw)
        except Exception as e:
            QtWidgets.QMessageBox.information(None, 'aCrypt - сообщение', 'Не удалось выполнить операцию; Сообщение: ' + repr(e))

            # Где случилась ошибка
            print(f'[!] ERROR @ {datetime.now().strftime("%H:%M:%S")} // Full traceback:')
            traceback.print_tb(e.__traceback__)
    return inner

# Сохраняет главный прогресс
def saveProgress():
    progressSaveFile = open(rpath(f'savedata/{PROGRESS_SAVE_NAME}'), 'w', -1, 'utf-8')
    progressSaveFile.write('|'.join([
        str(currentLevel),
        str(currentProgress)
    ]))
    progressSaveFile.close()

# Меняет тему в соответствии IS_DARK_THEME
def changeTheme():
    app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyside6', palette=[qdarkstyle.LightPalette, qdarkstyle.DarkPalette][IS_DARK_THEME]))
    if mainWindow:
        mainWindow.updateIcons()

# ----- Классы -----

# Оболочка главного окна
class MainWindowShell(QtWidgets.QMainWindow):
    def setRealObject(self, realObject):
        self.realObject = realObject

    def __init__(self):
        super().__init__()
    
    # Событие закрытия
    def closeEvent(self, e):
        if taskWindowShell is not None:
            QtWidgets.QMessageBox.information(self, 'aCrypt - сообщение', 'Задание в процессе выполнения. Сначала необходимо завершить окно с заданием.')
            e.ignore()
            return
        status = QtWidgets.QMessageBox.question(self, 'aCrypt - предупреждение', 'Данное действие сохранит ваш прогресс и закроет приложение. Вы уверены?')
        if status == QtWidgets.QMessageBox.Yes:
            # Сохранить всё
            saveProgress()

            # Закрыть все окна
            for i in secondaryWindows:
                print(f'Closing {type(i).__name__}')
                if 'Shell' in str(type(i)):
                    safeFunc(i.close)()
                else:
                    safeFunc(i.window.close)()
            if infoWindow: # infoWindow - простое окно
                print('Closing InfoWindow')
                safeFunc(infoWindow.window.close)()
            if taskWindowShell: # taskWindow - комплексное окно
                print('Closing TaskWindowShell')
                safeFunc(taskWindowShell.close)()

            app.processEvents()

            e.accept()
        else:
            e.ignore()

# Главное окно
class MainWindow:
    def updateText(self):
        self.window.progressLabel.setText(f'Прогресс: {str(currentProgress)} / {USER_LEVEL_DICT[currentLevel][1]}')
        self.window.levelLabel.setText(f'Ваш уровень: {str(currentLevel)} — {USER_LEVEL_DICT[currentLevel][0]}')

    def updateIcons(self):
        self.window.taskIcon.setPixmap(QtGui.QPixmap(rpath(f'resources/img/task{IS_DARK_THEME}.png')))
        self.window.booksIcon.setPixmap(QtGui.QPixmap(rpath(f'resources/img/books{IS_DARK_THEME}.png')))
        self.window.simulationIcon.setPixmap(QtGui.QPixmap(rpath(f'resources/img/simulation{IS_DARK_THEME}.png')))
        self.window.themeSelector.setIcon(QtGui.QIcon(QtGui.QPixmap(rpath(f'resources/img/theme{IS_DARK_THEME}.png'))))

    def __init__(self):
        self.window = loader.load(rpath('resources/main_window.ui'), None)

        # Иконки
        self.updateIcons()

        # Прогресс
        self.updateText()
        
        # Приветствие
        hour = datetime.now().hour
        greeting = 'Доброго времени'
        if hour in range(5, 11 + 1):
            greeting = 'Доброе утро'
        elif hour in range(12, 17 + 1):
            greeting = 'Добрый день'
        elif hour in range(18, 22 + 1):
            greeting = 'Добрый вечер'
        else:
            greeting = 'Доброй ночи'
        self.window.welcomeLabel.setText(f'{greeting}, {getuser()}')

        # Сменить тему
        def themeSelectorClick():
            global IS_DARK_THEME
            IS_DARK_THEME = int(not bool(IS_DARK_THEME))
            changeTheme()

            isDarkThemeSaveFile = open(rpath(f'savedata/{IS_DARK_THEME_SAVE_NAME}'), 'w', -1, 'utf-8')
            isDarkThemeSaveFile.write(str(IS_DARK_THEME))
            isDarkThemeSaveFile.close()
        self.window.themeSelector.clicked.connect(themeSelectorClick)

        # Сигнал на открытие библиотеки
        def knowledgeButtonClick():
            LibraryWindowObject = LibraryWindow()
            secondaryWindows.append(LibraryWindowObject)
            LibraryWindowObject.window.show()
        self.window.knowledgeButton.clicked.connect(knowledgeButtonClick)

        # Сигнал на открытие шифратора
        def simulationButtonClick():
            SimulationWindowObject, SimulationWindowShellObject = makeComplexWindow(SimulationWindow, SimulationWindowShell)
            secondaryWindows.append(SimulationWindowShellObject)
        self.window.simulationButton.clicked.connect(simulationButtonClick)

        # Сигнал на открытие "О приложении"
        def infoButtonClick():
            global infoWindow
            infoWindow = InfoWindow()
            infoWindow.window.show()
        self.window.infoButton.clicked.connect(infoButtonClick)

        # Сигнал на запрос повышения уровня
        def levelButtonClick():
            global currentProgress, currentLevel
            if currentProgress == USER_LEVEL_DICT[currentLevel][1]:
                if currentLevel == USER_MAX_LEVEL:
                    QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Поздравления!\nВы прошли весь курс, встроенный в aCrypt.\n\nЯ искренне надеюсь, что вы извлекли много пользы из моего труда. c:\n\nУспехов в применении полученных знаний!')
                    return
                currentLevel += 1
                currentProgress = 0
                saveProgress()
                self.updateText()
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', f'Поздравляем! Теперь вы на уровне {USER_LEVEL_DICT[currentLevel][0]}.')
            else:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', f'Недостаточно прогресса по заданиям. Пройдите еще {USER_LEVEL_DICT[currentLevel][1] - currentProgress}, чтобы перейти на следующий уровень.')
        self.window.levelButton.clicked.connect(levelButtonClick)

        # Сигнал на запрос на задание
        def taskButtonClick():
            global taskWindowShell

            # Предотвратить создание окна, если нет заданий
            # В финальной версии отсуствие задания будет означать, все задания на данном уровне пройдены
            taskKey = (currentLevel, currentProgress)
            if not TASK_DICT.get(taskKey, False):
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', f'Вы прошли все задания на данном уровне!')
                return

            if taskWindowShell:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Задание уже в процессе выполнения.')
                taskWindowShell.raise_()
                taskWindowShell.activateWindow()
            else:
                taskWindow, taskWindowShell = makeComplexWindow(TaskWindow, TaskWindowShell)
        self.window.taskButton.clicked.connect(taskButtonClick)

# Библиотека
class LibraryWindow:
    def __init__(self):
        self.window = loader.load(rpath('resources/library_window.ui'), None)
        self.currentDocument = ''

        # Окно удаляется при закрытии, чтобы не занимать память
        self.window.setAttribute(Qt.WA_DeleteOnClose)

        # Установить основную планировку библиотеки
        setWidgetLayout(self.window, '', 'horizontalLayout', ['leftFrame', 'textEdit'])
        # Установить планировку левой панели
        setWidgetLayout(self.window, 'leftFrame', 'verticalLayout', ['listView', 'openLastButton', 'changeFontButton'])

        # Наполнение списка документов
        for fileName in os.listdir(rpath('resources/txt')):
            if fileName.endswith('.txt'):
                self.window.listView.addItem(fileName[:-4])

        # Сигнал по выбору документа
        def documentSelect(item, saveThis = True):
            if self.currentDocument == item.text():
                return
            self.currentDocument = item.text()

            textFile = open(rpath(f'resources/txt/{item.text()}.txt'), 'r', -1, 'utf-8')

            self.window.textEdit.setMarkdown(''.join(textFile.readlines()).replace('![IMAGE_FILE](', f'![IMAGE_FILE]({rpath("resources").replace(BACKSLASH, "/")}'))
            textFile.close()

            # Сохранить последний открытый документ
            if saveThis:
                libLastSaveFile = open(rpath(f'savedata/{LIBRARY_LAST_SAVE_NAME}'), 'w', -1, 'utf-8')
                libLastSaveFile.write(item.text())
                libLastSaveFile.close()
        self.window.listView.itemActivated.connect(documentSelect)

        # Сигнал по запросу открыть последний документ
        def openLastDocument():
            lastSaveFile = None
            try:
                lastSaveFile = open(rpath(f'savedata/{LIBRARY_LAST_SAVE_NAME}'), 'r', -1, 'utf-8')
            except:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Вы не открывали ещё ни одного документа.')
            else:
                data = lastSaveFile.readline()
                lastSaveFile.close()

                if data == self.currentDocument:
                    return
                self.currentDocument = data

                textFile = open(rpath(f'resources/txt/{data}.txt'), 'r', -1, 'utf-8')
                self.window.textEdit.setMarkdown(''.join(textFile.readlines()).replace('![IMAGE_FILE](', f'![IMAGE_FILE]({rpath("resources").replace(BACKSLASH, "/")}'))
                textFile.close()
        self.window.openLastButton.clicked.connect(openLastDocument)

        # Если есть сохранённый шрифт, то установить его
        fontSaveFile = None
        try:
            fontSaveFile = open(rpath(f'savedata/{LIBRARY_FONT_SAVE_NAME}'), 'r', -1, 'utf-8')
        except:
            pass
        else:
            data = fontSaveFile.readline().split('|')
            fontSaveFile.close()

            newFont = QtGui.QFont(data[0], float(data[2]), FONT_WEIGHT_DICT[int(data[6])], bool(int(data[5])))
            newFont.setStrikeOut(bool(int(data[4])))
            newFont.setUnderline(bool(int(data[3])))
            if int(data[1]) != -1 and float(data[2]) == -1.0:
                newFont.setPixelSize(int(data[1]))
            self.window.textEdit.setFont(newFont)

        # Сигнал по запросу изменить шрифт
        def changeFontButtonClick():
            confirmed, newFont = QtWidgets.QFontDialog.getFont(self.window.textEdit.font(), None, 'Выберите новый шрифт')
            if confirmed:
                self.window.textEdit.setFont(newFont)

                # Задать шрифт другим окнам
                for i in secondaryWindows:
                    safeFunc(i.window.textEdit.setFont)(newFont)

                # Сохранить новый шрифт
                libFontSaveFile = open(rpath(f'savedata/{LIBRARY_FONT_SAVE_NAME}'), 'w', -1, 'utf-8')
                libFontSaveFile.write('|'.join([
                    newFont.family(),
                    str(newFont.pixelSize()),
                    str(newFont.pointSizeF()),
                    str(int(newFont.underline())),
                    str(int(newFont.strikeOut())),
                    str(int(newFont.italic())),
                    str(newFont.weight())
                ]))
                libFontSaveFile.close()
        self.window.changeFontButton.clicked.connect(changeFontButtonClick)

        # Новый размер
        self.window.setMinimumSize(self.window.width() + 256, self.window.height() + 128)

# Оболочка шифратора
class SimulationWindowShell(QtWidgets.QMainWindow):
    def setRealObject(self, realObject):
        self.realObject = realObject

    def __init__(self):
        super().__init__()
    
    # Событие закрытия
    def closeEvent(self, e):
        # Сохранить данные
        simLastSaveFile = open(rpath(f'savedata/{SIMULATION_LAST_SAVE_NAME}'), 'w', -1, 'utf-8')
        simLastSaveFile.write(thingy.join([
            self.realObject.mode,
            self.realObject.algorithm,
            self.realObject.window.keyLineEdit.text(),
            self.realObject.window.auxLineEdit.text(),
            self.realObject.window.encryptInputTextEdit.toPlainText(),
            self.realObject.window.encryptOutputTextEdit.toPlainText(),
            self.realObject.window.decryptInputTextEdit.toPlainText(),
            self.realObject.window.decryptOutputTextEdit.toPlainText()
        ]))
        simLastSaveFile.close()

        e.accept()

# Шифратор
class SimulationWindow:
    # Смена режимов
    def activateDecrypt(self):
        self.window.encryptFrame.hide()
        self.window.decryptFrame.show()
        self.mode = 'decrypt'
    def activateEncrypt(self):
        self.window.decryptFrame.hide()
        self.window.encryptFrame.show()
        self.mode = 'encrypt'

    def __init__(self):
        self.window = loader.load(rpath('resources/simulation_window.ui'), None)
        self.mode = 'encrypt'
        self.algorithm = ''

        self.window.decryptFrame.hide()

        # Окно удаляется при закрытии, чтобы не занимать память
        self.window.setAttribute(Qt.WA_DeleteOnClose)

        # Установить основную планировку шифратора
        setWidgetLayout(self.window, '', 'verticalLayout', ['encryptFrame', 'decryptFrame', 'radioButtonFrame', 'algorithmComboBox', 'parameterLengthFrame', 'parameterFrame', 'actionButton'])
        # Установить планировку энкриптера
        setWidgetLayout(self.window, 'encryptFrame', 'encryptHorizontalLayout', ['encryptInputTextEdit', 'encryptOutputTextEdit'])
        # Установить планировку декриптера
        setWidgetLayout(self.window, 'decryptFrame', 'decryptHorizontalLayout', ['decryptInputTextEdit', 'decryptOutputTextEdit'])
        # Установить планировку панели c кнопками
        setWidgetLayout(self.window, 'radioButtonFrame', 'radioButtonHorizontalLayout', ['decryptRadioButton', 'encryptRadioButton'])
        # Установить планировку панели с параметрами
        setWidgetLayout(self.window, 'parameterFrame', 'parameterHorizontalLayout', ['keyLineEdit', 'auxLineEdit'])
        # Установить планировку панели с длинной параметров
        setWidgetLayout(self.window, 'parameterLengthFrame', 'parameterLengthHorizontalLayout', ['keyLengthLabel', 'auxLengthLabel'])

        # Наполнение выборщика
        for i in ALGORITHM_DICT.keys():
            self.window.algorithmComboBox.addItem(i)
        # Сигнал по выбору в выборщике
        def algorithmSelect(text):
            self.algorithm = text
        self.window.algorithmComboBox.currentTextChanged.connect(algorithmSelect)

        # Сигналы по нажатию радио кнопок
        self.window.decryptRadioButton.toggled.connect(self.activateDecrypt)
        self.window.encryptRadioButton.toggled.connect(self.activateEncrypt)

        # Сигналы на изменение длины
        def keyLengthChanged(txt):
            self.window.keyLengthLabel.setText(str(len(txt)))
        self.window.keyLineEdit.textChanged.connect(keyLengthChanged)
        def auxLengthChanged(txt):
            self.window.auxLengthLabel.setText(str(len(txt)))
        self.window.auxLineEdit.textChanged.connect(auxLengthChanged)

        # Сигнал по нажатию кнопки действия
        def actionButtonClick():
            if not self.algorithm:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Не выбран алгоритм шифрования.')
                return
            
            inputTextEdit = getattr(self.window, f'{self.mode}InputTextEdit')
            inputText = inputTextEdit.toPlainText()

            if not inputTextEdit.toPlainText():
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Отсутствуют входные данные.')
                return
            
            outputTextEdit = getattr(self.window, f'{self.mode}OutputTextEdit')

            algorithmData = ALGORITHM_DICT[self.algorithm]

            # Если ключа нет, а для него есть сообщение об ошибке
            if not self.window.keyLineEdit.text() and len(algorithmData) >= 5:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', algorithmData[4])
                return
        
            # Если доп. параметра нет, а для него есть сообщение об ошибке
            # и нет дефолта
            if not self.window.auxLineEdit.text() and len(algorithmData) >= 6 and len(algorithmData) < 7:
                QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', algorithmData[5])
                return

            # Если ключ не требуется
            if not algorithmData[2]:
                outputTextEdit.setPlainText(safeFuncWAlert(algorithmData[{'encrypt':0, 'decrypt':1}[self.mode]])(inputText))
            # Если ключ требуется, но без доп. параметра
            elif algorithmData[2] and not algorithmData[3]:
                outputTextEdit.setPlainText(safeFuncWAlert(algorithmData[{'encrypt':0, 'decrypt':1}[self.mode]])(inputText, self.window.keyLineEdit.text()))
            # Если требуется доп. параметр
            else:
                outputTextEdit.setPlainText(safeFuncWAlert(algorithmData[{'encrypt':0, 'decrypt':1}[self.mode]])(inputText, self.window.keyLineEdit.text(), self.window.auxLineEdit.text() or algorithmData[6]))
        self.window.actionButton.clicked.connect(actionButtonClick)

        # Загрузка сохранённых данных, если они есть
        simLastSaveFile = None
        try:
            simLastSaveFile = open(rpath(f'savedata/{SIMULATION_LAST_SAVE_NAME}'), 'r', -1, 'utf-8')
        except:
            pass
        else:
            data = ''.join(simLastSaveFile.readlines()).split(thingy)
            simLastSaveFile.close()

            getattr(self, f'activate{data[0].title()}')()
            getattr(self.window, f'{data[0]}RadioButton').setChecked(True)
            if data[1]:
                self.window.algorithmComboBox.setCurrentText(data[1])
            self.window.keyLineEdit.setText(data[2])
            self.window.auxLineEdit.setText(data[3])
            self.window.encryptInputTextEdit.setPlainText(data[4])
            self.window.encryptOutputTextEdit.setPlainText(data[5])
            self.window.decryptInputTextEdit.setPlainText(data[6])
            self.window.decryptOutputTextEdit.setPlainText(data[7])

# Оболочка окна с заданием
class TaskWindowShell(QtWidgets.QMainWindow):
    def setRealObject(self, realObject):
        self.realObject = realObject

    def __init__(self):
        global taskWindowShell
        taskWindowShell = self
        super().__init__()
    
    # Событие закрытия
    def closeEvent(self, e):
        global taskWindowShell
        
        status = QtWidgets.QMessageBox.question(self, 'aCrypt - предупреждение', 'Данное действие закроет задание. Вы уверены?')
        if status == QtWidgets.QMessageBox.Yes:
            taskWindowShell = None
            e.accept()
        e.ignore()

# Окно с заданием
class TaskWindow:
    def __init__(self):
        # Процесс инициализации по данным задания
        taskKey = (currentLevel, currentProgress)
        taskData = TASK_DICT.get(taskKey)

        self.window = None
        if taskData[0] == 'task_window.ui':
            self.window = loader.load(rpath('resources/task_window.ui'), None)

            # Планировка
            setWidgetLayout(self.window, '', 'verticalLayout', ['taskLabel', 'taskTextEdit', 'answerLabel', 'answerTextEdit', 'answerButton'])

            # Установка под задание
            taskData[1] = taskData[1].replace('![IMAGE_FILE](', f'![IMAGE_FILE]({rpath("resources").replace(BACKSLASH, "/")}')
            if taskData[3] is not None:
                self.window.taskTextEdit.setMarkdown(taskData[1] + f'\n\n****\n\n(В ответе регистр {["НЕ ИМЕЕТ значения", "ИМЕЕТ значение"][int(taskData[3])]}.)')
            else:
                self.window.taskTextEdit.setMarkdown(taskData[1])

            # Сигнал по нажатию кнопки "Проверить"
            def checkAnswer():
                global currentProgress, taskWindowShell

                userAnswer = self.window.answerTextEdit.toPlainText()
                correctAnswer = taskData[2]

                # Отсеиваем попутно ответы, где лямбда функция крашится
                try:
                    if not taskData[3]:
                        userAnswer = userAnswer.lower()
                        if type(correctAnswer).__name__ != 'function':
                            correctAnswer = correctAnswer.lower()
                    if userAnswer == correctAnswer or (type(correctAnswer).__name__ == 'function' and correctAnswer(userAnswer)):
                        QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Ответ верный! Задание засчитано.')
                        currentProgress += 1
                        saveProgress()
                        mainWindow.updateText()
                        taskWindowShell = None
                    else:
                        QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Ответ неверный. Перепроверьте ваш ответ и попробуйте ещё раз.')
                except Exception as e:
                        QtWidgets.QMessageBox.information(self.window, 'aCrypt - сообщение', 'Ответ неверный. Перепроверьте ваш ответ и попробуйте ещё раз.')
                        
                        # Где случилась ошибка
                        print(f'[!] ERROR @ {datetime.now().strftime("%H:%M:%S")} // Full traceback:')
                        traceback.print_tb(e.__traceback__)
                        
                        return
            self.window.answerButton.clicked.connect(checkAnswer)
        
        # Окно удаляется при закрытии, чтобы не занимать память
        self.window.setAttribute(Qt.WA_DeleteOnClose)

# Окно "О приложении"
class InfoWindow:
    def __init__(self):
        self.window = loader.load(rpath('resources/about_window.ui'), None)

        # Окно удаляется при закрытии, чтобы не занимать память
        self.window.setAttribute(Qt.WA_DeleteOnClose)

        # Планировка
        setWidgetLayout(self.window, '', 'verticalLayout', ['titleLabel', 'descLabel', 'textEdit'])
        
        aboutFile = open(rpath(f'resources/internal_txt/about.txt'), 'r', -1, 'utf-8')
        self.window.textEdit.setMarkdown(''.join(aboutFile.readlines()))
        aboutFile.close()

# ----- Установочные переменные -----

loader = QUiLoader()

app = QtWidgets.QApplication(sys.argv)

# Добавить шрифты в библиотеку

for r, ds, fs in os.walk(rpath('resources/fonts')):
    for f in fs:
        QtGui.QFontDatabase.addApplicationFont(os.path.join(r, f))
        print(f'Загружен шрифт: {f}')


# ----- Тема -----

isDarkThemeSaveFile = None
try:
    isDarkThemeSaveFile = open(rpath(f'savedata/{IS_DARK_THEME_SAVE_NAME}'), 'r', -1, 'utf-8')
except:
    isDarkThemeSaveFile = open(rpath(f'savedata/{IS_DARK_THEME_SAVE_NAME}'), 'w', -1, 'utf-8')
    isDarkThemeSaveFile.write(str(IS_DARK_THEME))
    isDarkThemeSaveFile.close()
else:
    data = isDarkThemeSaveFile.readline()
    isDarkThemeSaveFile.close()

    IS_DARK_THEME = int(data)

changeTheme()

# ----- Предустановки -----

# Если есть данные по прогрессу, то загрузить их
progressSaveFile = None
try:
    progressSaveFile = open(rpath(f'savedata/{PROGRESS_SAVE_NAME}'), 'r', -1, 'utf-8')
except:
    QtWidgets.QMessageBox.information(None, 'aCrypt - добро пожаловать', 'Если вы видите это сообщение, то это значит что вы в первый раз запускаете aCrypt.\n\nЭто сообщение предназначено проинформировать вас перед появлением главного интерфейса; рекомендуется нажать на кнопку "О приложении", перед тем как начинать. Так вы сможете прочитать краткое описание, предназначение и разъяснение различных элементов интерфейса.\n\nЯ желаю удачи вам в познании симметричного шифрования!')
else:
    data = progressSaveFile.readline().split('|')
    currentLevel = int(data[0])
    currentProgress = int(data[1])
    progressSaveFile.close()

# ----- Открытие главного окна и существование главного цикла -----

mainWindow, mainWindowShell = makeComplexWindow(MainWindow, MainWindowShell)

sys.exit(app.exec())