import hmac
import random
import string
from _hashlib import pbkdf2_hmac
from itertools import cycle
from timeit import default_timer as timer
from types import ModuleType

from colorama import Fore, init
import base64

init(autoreset=True)
debug = True


class CodeBrute:
    """
    Conceal source code with a pin, brute at runtime, decrypt code, then execute
    Brute force a 4 digit pin and then decrypt and execute (xor||aes) encrypted code
    """

    def __init__(self, hash_str, salt):
        """
        Init class with pin's salt and hash
        :param hash_str: str
        :param salt: str
        """
        self.hash = hash_str
        self.salt = salt

    def b64_xor_crypt(self, data, key, mode):
        """
        Xor Encryption / Decryption
        :param mode: encrypt / decrypt (for base64)
        :param data: en/de crypt this data
        :param key: with this key
        :return: str(crypted data)
        """
        if mode == 'dec':
            data = base64.b64decode(data)
        elif mode == 'enc':
            data = base64.b64encode(data)
        data = data.decode()

        return ''.join(chr(ord(str(a)) ^ ord(str(b))) for (a, b) in zip(data, cycle(key)))

    def decrypt_and_execute(self, cipher_text, _pin):
        """
        Xor decrypt and execute code
        :param cipher_text: xor encrypted module
        :param _pin: 4 digit pin (key)
        :return:
        """
        code = self.b64_xor_crypt(cipher_text, _pin, 'dec')
        shell_code = ModuleType('shell')
        exec(code, globals(), shell_code.__dict__)
        shell_code.Shell.shell()  # module shell_code > class Shell: > function shell()

    def check_password(self, password: str) -> bool:
        """
        Given a previously-stored salt and hash, check whether the password is correct.
        :param password: key to check
        :return: bool
        """

        return hmac.compare_digest(
            bytes.fromhex(self.hash),
            pbkdf2_hmac('sha1', password.encode(), bytes.fromhex(self.salt), 100000))

    def generate(self, size=4, chars=string.digits):
        """

        :param size: length of pin
        :param chars: characters (digits)
        :return: iter object
        """
        generated = []
        for n in range(0000, 9999):
            while True:
                pin = ''.join(random.choice(chars) for x in range(size))
                if pin not in generated:
                    generated.append(pin)
                    yield (pin)

    def check(self, key):
        if self.check_password(key):
            return True
        return False

    def brute(self):
        count = 0
        lst = self.generate()
        for i in lst:
            count += 1
            if self.check(i):
                print('Found password:', i)
                return i, count
            if debug:
                print(f'Fail: {i} Count: {count}')


def main():
    """
    Brute, decrypt xor code, execute module.
    """
    hash_str = '5411ba21c470e12d49f351a2d240e43618032950'
    salt = '0d71906d0f735e6196c80d0a7cb1748e'
    encrypted_code = 'Ul5SR0ISYFxUXl8OOxITFBFWVlIRQVtRXV4bHQs4ExQREhMUERJDRlhcRxwWZltdQhJaRxFTE0BUQUcUXF1XQV1XFB07EhMUE' \
                     'RITFBFCQV1fRhsTZVdAQBFhRldSV0BHV0dfGhYbOQ=='
    bruter = CodeBrute(hash_str, salt)
    start = timer()
    _key, iterations = bruter.brute()
    print('Found', _key)
    print('Attempts:', iterations)
    elapsed = timer() - start
    print('Time:', elapsed)
    bruter.decrypt_and_execute(encrypted_code, str(_key))


if __name__ == '__main__':
    main()
