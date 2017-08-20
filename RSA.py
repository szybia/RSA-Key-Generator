from random import randrange
from random import SystemRandom


def rabin_miller(number):
    num1 = number - 1
    num2 = 0
    while num1 % 2 == 0:
        num1 //= 2
        num2 += 1

    for i in range(5):
        random_num = randrange(2, number - 1)
        remainder = pow(random_num, num1, number)
        if remainder != 1:
            i = 0
            while remainder != (number - 1):
                if i == num2 - 1:
                    return False
                else:
                    i += 1
                    remainder = (remainder ** 2) % number
    return True


def is_prime(num):
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
              61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
              131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
              197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
              271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
              353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
              433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
              509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
              601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673,
              677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
              769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
              859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
              953, 967, 971, 977, 983, 991, 997]

    for prime in primes:
        if num % prime == 0:
            return False

    return rabin_miller(num)


# Return a random prime number with given number of bits
def prime_generator(bitsize=1024):
    while 1:
        number = randrange(2 ** (bitsize - 1), 2 ** bitsize)
        if is_prime(number):
            return number


# Euclidean Algorithm
def gcd(num1, num2):
    while num2 != 0:
        temp = num1
        num1 = num2
        num2 = temp % num2
    return num1


# Extended Euclidean Algorithm
def xgcd(number, mod):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while mod != 0:
        q, number, mod = number // mod, mod, number % mod
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0


def padding(plaintext):
    encoding = ""
    num_required = 611 - len(str(plaintext))
    encoding += str(SystemRandom().randrange(int("1" + ("0" * (num_required-1))), int("9" + ("9" * (num_required-1)))))
    encoding = encoding.replace("0", str(SystemRandom().randrange(1, 9)))
    encoding = "0002" + encoding + "00"
    encoding += str(plaintext)
    return int(encoding)


def remove_padding(ciphertext):
    ciphertext = str(ciphertext)
    ciphertext = ciphertext[ciphertext.find("00")+2:]
    return str(hex(int(ciphertext)))[2:]


def encryption(plaintext, e, N):
    hex_plain = ""
    if len(plaintext) > 600:
        print("Message too long.")
        return
    for letter in plaintext:
        hex_plain += hex(ord(letter))[2:]
    plaintext = int(hex_plain, 16)
    if len(str(plaintext)) >= len(str(N)):
        print("Text is too long.")
        return
    plaintext = padding(plaintext)
    return pow(plaintext, e, N)


def decryption(ciphertext, d, N):
    ciphertext = pow(ciphertext, d, N)
    ciphertext = remove_padding(ciphertext)
    cleartext = ""
    i = 0
    for number in range(int(len(ciphertext)/2)):
        cleartext += chr(int(ciphertext[i:i+2], 16))
        i += 2
    return cleartext


# MAIN
if __name__ == "__main__":

    check = True

    while check:
        # First Private Key (Length of key in bits)
        p = prime_generator(1024)

        # Second Private Key
        q = prime_generator(1024)

        # Encryption Number
        e = 65537

        if p % e != 1 and q % e != 1 and p != q:
            check = False

    # Public Key Mod (pq)
    N = p * q

    # Euler's totient function φ(n)
    phiN = (p - 1) * (q - 1)

    # Decryption Number
    # Modular Inverse of e mod phiN
    check = True
    d = xgcd(e, phiN)

    # Since d can't be negative perform a check
    while check:
        if d < 0:
            d += phiN
        else:
            check = False

    print("\nYour Public Key (n, e):")
    print(tuple([N, e]))

    print("\nKEEP ALL VALUES UNDER THIS MESSAGE SECRET!!!\n")
    print("Your Private Key (n, d):")
    print(tuple([N, d]))

    print("\np : {}\nq : {}".format(p, q))

    # Sample Encryption and Decryption functions

    message = "Attack at Dawn."
    ciphertext = encryption(message, e, N)
    print("\nCleartext: {}".format(message))
    print("CipherText: {}".format(hex(int(ciphertext))))
    cleartext = decryption(ciphertext, d, N)
    print("Cleartext: {}\n".format(cleartext))

    ciphertext = encryption(message, e, N)
    print("\nCleartext: {}".format(message))
    print("CipherText: {}".format(hex(int(ciphertext))))
    cleartext = decryption(ciphertext, d, N)
    print("Cleartext: {}\n".format(cleartext))