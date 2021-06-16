# Created based on:
# https://www.geeksforgeeks.org/rsa-algorithm-cryptography/

from random import randint
import sys

DEBUG = True  # Define False to get random integers
CONSTANT_DEFAULT_NUMBER = 2


def is_prime(number):
    if number == 2:
        return True
    elif (number < 2 or number % 2 == 0):
        return False
    elif number > 2:
        for i in range(2, number):
            if not number % i:
                return False

    return True


def compute_gcd(a, b):
    while b:
        a, b = b, a % b

    return a


class RSA():

    def __init__(self, p, q):
        assert is_prime(p)
        assert is_prime(q)

        self.p = p
        self.q = q
        self.rsa_modules_e = 2
        self.rsa_modules_n = self.p * self.q
        self._calculate_keys()

    @property
    def eulers_toitent(self):
        return (self.p - 1) * (self.q - 1)

    def __calculate_gcd(self):
        eulers_toitent = self.eulers_toitent

        while self.rsa_modules_e < eulers_toitent:
            if compute_gcd(self.rsa_modules_e, eulers_toitent) == 1:
                break

            self.rsa_modules_e += 1

    def _calculate_keys(self):
        self.__calculate_gcd()

        self.private_key = int(
            (CONSTANT_DEFAULT_NUMBER * self.eulers_toitent + 1) / self.rsa_modules_e)

    def encrypt(self, text_to_encrypt):
        letters_as_number = [ord(letter.lower()) -
                             96 for letter in text_to_encrypt]
        numbers_as_string = ''.join(map(str, letters_as_number))
        number_pow_of_e = int(numbers_as_string) ** self.rsa_modules_e
        return int(number_pow_of_e % self.rsa_modules_n)

    def decrypt(self, encrypted_text):
        text_pow_of_e = encrypted_text ** self.private_key
        result_as_number = text_pow_of_e % self.rsa_modules_n
        number_as_letters = [chr(int(num) + 96)
                             for num in str(result_as_number)]
        return ''.join(number_as_letters)

    def __str__(self):
        return '''private_key={}, rsa_modules_n={}, rsa_modules_e={}
        '''.format(self.private_key, self.rsa_modules_n, self.rsa_modules_e)


def main():
    rsa = RSA(53, 59)
    result = rsa.encrypt('HI')
    print('encrypt', result)
    print('decrypt', rsa.decrypt(result))
    print('str -> ', str(rsa))


if __name__ == '__main__':
    main()
