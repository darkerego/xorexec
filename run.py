#!/usr/bin/env python3
##########################
# Darkerego, 2019 - 2025
###########################
# https://github.com/darkerego

import argparse
import base64
import hmac
from _hashlib import pbkdf2_hmac
from itertools import cycle
from timeit import default_timer as timer
from types import ModuleType
from typing import Any

# Define constant variables
HASH_STR = '5411ba21c470e12d49f351a2d240e43618032950'
SALT_STR = '0d71906d0f735e6196c80d0a7cb1748e'
# b64 wrapped xor encrypted shellcode
ENC_BIN = 'Ul5SR0ISYFxUXl8OOxITFBFWVlIRQVtRXV4bHQs4ExQREhMUERJDRlhcRxwWZltdQhJaRx'
ENC_BIN += 'FTE0BUQUcUXF1XQV1XFB07EhMUERITFBFCQV1fRhsTZVdAQBFhRldSV0BHV0dfGhYbOQ=='


class CodeBrute:
    """
    Conceal source code with a pin, brute at runtime, decrypt code, then execute
    Brute force a 4-digit pin and then decrypt and execute (xor||aes) encrypted code
    """

    def __init__(self, hash_str: str = HASH_STR,
                 salt: str = SALT_STR,
                 encrypted_code: str = ENC_BIN,
                 debug: bool = False):
        """
        Init class with pin's salt and hash
        :param hash_str: str
        :param salt:
        """
        self.count = 0
        self.key = None
        self.hash = hash_str
        self.salt = salt
        self.encrypted_code = encrypted_code
        self.debug = debug

    def debug_print(self, data: Any):
        if self.debug:
            print(str(data))

    def b64_xor_crypt(self, data: str, key: str, mode: str) -> str | None:
        """
        Xor Encryption / Decryption
        :param mode: encrypt / decrypt (for base64)
        :param data: en/de crypt this data
        :param key: with this key
        :return: str(crypted data)
        """
        assert mode in ('encrypt', 'decrypt')
        if mode in ['enc', 'encrypt']:
            _data: str = ''.join((chr(ord(str(a)) ^ ord(str(b))) for (a, b) in zip(data, cycle(key))))
            return base64.b64encode(_data.encode()).decode()
        elif mode in ['dec', 'decrypt']:
            __data = base64.b64decode(data).decode()
            return ''.join((chr(ord(str(a)) ^ ord(str(b))) for (a, b) in zip(__data, cycle(key))))
        return None

    def decrypt_and_execute(self, cipher_text: str, _pin: str):
        """
        Xor decrypt and execute code
        :param cipher_text: xor encrypted module
        :param _pin: 4 digit pin (key)
        :return:
        """
        code = self.b64_xor_crypt(cipher_text, _pin, 'decrypt')
        self.debug_print('Executing:\n' + code)
        shell_code = ModuleType('shell')
        exec(code, globals(), shell_code.__dict__)
        shell_code.Shell.shell()  # module shell_code > class Shell: > function shell()

    def check_password(self, password: str) -> bool:
        """
        Given a previously stored salt and hash, check whether the password is correct.
        :param password: Key to check
        :return: bool
        """

        return hmac.compare_digest(
            bytes.fromhex(self.hash),
            pbkdf2_hmac('sha1', password.encode(), bytes.fromhex(self.salt), 100000))

    def generate(self):
        """
        :return: generator
        """
        for n in range(1000, 9999):
            yield str(n)

    def check(self, key: str) -> bool:
        if self.check_password(key):
            self.key = key
            return True
        return False

    def brute(self):
        """
        Brute force a 4-digit pin
        @return: string representation of 4-digit pin
        """
        self.count = 0

        def check(i):
            """
            Wraps check logic into a single function so that I can call it using list comprehension for
            way faster performance
            """
            self.count += 1
            if self.check(i):
                self.debug_print('Found password: %s Attempts: %s' % (self.key, self.count))
                return self.key
            return 0

        # stop iterating if self.key is assigned
        [check(i) for i in self.generate() if not self.key]
        return self.key

    def main(self):
        """
        Brute, decrypt xor code, execute module.
        """
        start = timer()
        _key = self.brute()
        print('Found', _key)
        elapsed = timer() - start
        print('Time:', elapsed)
        self.decrypt_and_execute(self.encrypted_code, str(_key))


if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('--debug', action='store_true')
    args = args.parse_args()
    CodeBrute(HASH_STR, SALT_STR, ENC_BIN, debug=args.debug).main()
