# xorexec
Python3 library to bruteforce xor encrypted shellcode and then execute

Work in progress ... 

Test code used in example:

<pre>
class Shell:
    def shell():
        print('This is a test module')
        print('Test Successful.')

</pre>

Example run:

<pre>
$ python3 run.py
Found password: 1234
Found 1234
Attempts: 4997
Time: 136.63006368884817
This is a test module
Test Successful.

Process finished with exit code 0
</pre>
