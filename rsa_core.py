import random
from math import gcd

def is_prime(n, k=5):  # k = liczba testów (im więcej, tym większa pewność)
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # zapisz n − 1 jako 2^r · d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_keypair(bits=512):
    def get_prime():
        while True:
            num = random.getrandbits(bits)
            if is_prime(num):
                return num

    p = get_prime()
    q = get_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi)

    d = pow(e, -1, phi)

    return (e, n), (d, n)

def encrypt_block(m, pubkey):
    e, n = pubkey
    return pow(m, e, n)

def decrypt_block(c, privkey):
    d, n = privkey
    return pow(c, d, n)
