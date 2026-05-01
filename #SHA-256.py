#SHA-256

import struct

#Створюємо задані стандартом константи, 
# щоб потім використовувати їх в 64 раундах
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

#Створюємо початковий стан, кожне по 32 біти (h0,h1,h2,h3,h4,h5,h6,h7)
INITIAL_HASHES = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]

#Циклічний зсув вправо (останні біти переходять на початок)

def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256(message):
    #Перетворюємо текст на байти
    if isinstance(message, str):
        message = message.encode("utf-8")

    #Перетворюємо на bytearrey та зберігаємо першочергову довжину
    message = bytearray(message)
    original_bit_length = len(message) * 8

    #padding (додаємо один біт 1 і сім нульів)
    message.append(0x80)

    #додаємо нульові байти, поки довжина не буде 448 mod 512
    # (64 біти резервуємо для довжини повідомлення)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

    #Вже додаємо початкову довжину повідомлення як 64-бітне число)
    message += struct.pack(">Q", original_bit_length)

    #робимо копію початкового стану
    h = INITIAL_HASHES.copy()

    #SHA-256 обробляє блоки по 64 байти
    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]

        #перетворюємо блок з 64 байтів на 16 чисел по 32 біти
        w = list(struct.unpack(">16I", block))

        #створюємо ще 48 слів за формулою із стандарту (s0,s1 -- функції перемішування)
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        #переносимо внутрішній стан у вісім змінних
        a, b, c, d, e, f, g, hh = h

        #Основні 64 раунди перемішування
        for i in range(64):
            #Перша функція обертає біти на 6,11,25 позицій і ксорить результат
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            #Вибір між бітом g та f залежно від біта e
            ch = (e & f) ^ ((~e) & g)
            #Все змішуємо(поточна робоча змінна, перемішані біти, функція вибору,
            #  константа зі стандарту, слово повідомлення)
            temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff

            #Так само як S1 тільки бере змінну a
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            #Повертає більшість серед змінних a,b,c (якщо два біти 1, повертає 1)
            maj = (a & b) ^ (a & c) ^ (b & c)
            #Змішуємо s0 та функцію більшості
            temp2 = (S0 + maj) & 0xffffffff

            #оновлення робочих змінних(зсув), та обчислення e та a
            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        #Додаємо нові значення до старих в hash state
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + hh) & 0xffffffff

    #Формуємо хеш з 8 чисел по 32 біти
    return "".join(f"{value:08x}" for value in h)


#Перевірка реалізації за тестовими векторами
def run_tests():
    test_vectors = [
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ),
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        ),
        (
            b"a" * 1_000_000,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        ),
    ]

    for message, expected_hash in test_vectors:
        actual_hash = sha256(message)

        if actual_hash == expected_hash:
            print("PASS")
            print(actual_hash)
        else:
            print("FAIL")
            print("Expected:", expected_hash)
            print("Actual:  ", actual_hash)

#Перевірка знайденого префіксу
def test_prefix():
    message = b"give my friend 2 bitcoinsfor a pizza"

    prefix_hex = "4b53452d4353383130504f57000000004da5f4b9"
    #переводимо в байти префікс
    prefix = bytes.fromhex(prefix_hex)
    #обʼєднуʼмо префікс з повідомленням
    digest = sha256(prefix + message)

    print("Message:", message.decode())

    print("Prefix (hex):", prefix_hex)

    print("SHA-256:", digest)

    # перевірка 32 нулів на початку
    if digest.startswith("00000000"):
        print("Hash starts with 32 zero bits")
    else:
        print("FAIL")


if __name__ == "__main__":
    run_tests()
    print("\n--- Prefix test ---")
    test_prefix()