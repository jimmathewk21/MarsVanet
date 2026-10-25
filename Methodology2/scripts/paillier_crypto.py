from math import gcd
from secrets import randbelow
from sympy import randprime


def generate_keys(bits=256):
    if bits < 32:
        raise ValueError("Use at least 32 bits for functional tests")

    half = bits // 2

    while True:
        p = randprime(1 << (half - 1), 1 << half)
        q = randprime(1 << (half - 1), 1 << half)

        if p != q:
            n = p * q
            phi = (p - 1) * (q - 1)

            if gcd(phi, n) == 1:
                return (n, phi), (n,)


def encrypt(message, public_key):
    n, = public_key

    if not isinstance(message, int) or not 0 <= message < n:
        raise ValueError("Message must be an integer in [0, N)")

    n_squared = n * n

    while True:
        r = randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break

    ciphertext = (pow(1 + n, message, n_squared) *
                  pow(r, n, n_squared)) % n_squared

    return ciphertext


def decrypt(ciphertext, private_key):
    n, phi = private_key
    n_squared = n * n

    if not 0 <= ciphertext < n_squared or gcd(ciphertext, n) != 1:
        raise ValueError("Invalid Paillier ciphertext")

    powered = pow(ciphertext, phi, n_squared)
    numerator = powered - 1

    if numerator % n != 0:
        raise ValueError("Ciphertext does not satisfy the decryption equation")

    message_factor = (numerator // n) % n
    return (message_factor * pow(phi, -1, n)) % n


def add_ciphertexts(ciphertext_a, ciphertext_b, public_key):
    n, = public_key
    n_squared = n * n

    return (ciphertext_a * ciphertext_b) % n_squared
