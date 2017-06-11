import sys, random, pickle, math, base64
import numpy as np

sys.setrecursionlimit(10000000)


# usage notation
def print_usage(command = ''):
    if command == 'init':
        print 'init <keys_filename> <prime_length>'
    elif command == 'encrypt':
        print 'encrypt <keys_filename> <plaintext_filename> <ciphertext_filename>'
    elif command == 'decrypt':
        print 'decrypt <keys_filename> <ciphertext_filename> <decrypted_filename>'
    else:
        print 'Usage:'
        print '\tinit - rsa setup -> takes keys_filename and prime_length as inputs'
        print '\tencrypt -> takes keys_filename, plaintext_filename, and ciphertext_filename as inputs'
        print '\tdecrypt -> takes keys_filename, ciphertext_filename, and decrypted_filename as inputs '


# compute a^b % c
def fast_pow(x, n, m):
    a = 1
    b = x
    while True:
        temp = n

        if n % 2 == 1:
            a = a * b % m

        b = b * b % m
        n = n // 2

        if temp < 1:
            return a


def m_r(a, s, d, n):
    atop = pow(a, d, n)
    if atop == 1:
        return True
    for i in xrange(s - 1):
        if atop == n - 1:
            return True
        atop = (atop * atop) % n
    return atop == n - 1


def miller_rabin_test(n, confidence):
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range(confidence):
        a = 0
        while a == 0:
            a = random.randrange(n)
        if not m_r(a, s, d, n):
            return False
    return True


def _gcd(a, b):
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a


def extended_euclidean_algorithm(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = extended_euclidean_algorithm(b, a % b)
        return y, x - y * (a // b), gcd


def inverse_mod(a, m):
    x, y, gcd = extended_euclidean_algorithm(a, m)
    if gcd == 1:
        return x % m
    else:
        return None


class RSA(object):
    # the meta of key
    key_meta = dict()

    # primality test times
    primality_confidence = 20

    def genenerate_keys(self, filename, nbits):

        # generate p (nbits prime )
        while 1:
            p = random.getrandbits(nbits)
            if miller_rabin_test(p, self.primality_confidence):
                self.key_meta.update({'p': p})
                break

        # generate q (nbits prime )
        while 1:
            q = random.getrandbits(nbits)
            if miller_rabin_test(q, self.primality_confidence):
                self.key_meta.update({'q': q})
                break

        # compute modulus: ( p * q )
        modulus = long(self.key_meta['p'] * self.key_meta['q'])
        self.key_meta.update({'modulus': modulus})

        # compute phi(modulus): ( ( p - 1 )( q - 1 ) )
        phi = long((self.key_meta['p'] - 1) * (self.key_meta['q'] - 1))
        self.key_meta.update({'phi': phi})

        # choose e s.t 1 < e < phi and euclid_gcd( e, phi ) = 1
        while 1:

            # select e
            while 1:
                e = random.randrange(phi)
                if e == 0:
                    continue
                if _gcd(e, phi) == 1:
                    self.key_meta.update({'e': e})
                    self.key_meta.update({'pub_key': (modulus, e)})
                    break


            # compute d
            d = inverse_mod(long(self.key_meta['e']), phi)
            if d is None:
                continue
            else:
                self.key_meta.update({'d': long(d)})
                self.key_meta.update({'priv_key': (modulus, long(d))})
                break

        self.dump(filename)

    # encryption method
    def encrypt(self, keys_fn, plaintext_fn, ciphertext_fn):
        from time import clock
        t0 = clock()

        self.load(keys_fn)
        plaintext_handle = open(plaintext_fn, 'r')
        plaintext = plaintext_handle.read()
        plaintext_handle.close()
        pub_key = self.key_meta['pub_key']
        ciphertext = ''

        for char in plaintext:
            ciphertext += str(fast_pow(ord(char), pub_key[1], pub_key[0])) + ' '

        ciphertext_handle = open(ciphertext_fn, 'w')
        ciphertext_handle.write(ciphertext)
        ciphertext_handle.close()

        t1 = clock()
        print("Time used:")
        print(t1 - t0)

    # decryption method
    def decrypt(self, keys_fn, ciphertext_fn, decrypted_fn):
        from time import clock
        t0 = clock()

        self.load(keys_fn)
        ciphertext_handle = open(ciphertext_fn, 'r')
        ciphertext = ciphertext_handle.read().split()
        priv_key = self.key_meta['priv_key']
        decrypted = ''

        for chunk in ciphertext:
            x_p = long(chunk) % self.key_meta['p']
            x_q = long(chunk) % self.key_meta['q']
            d_p = self.key_meta['d'] % (self.key_meta['p'] - 1)
            d_q = self.key_meta['d'] % (self.key_meta['q'] - 1)
            y_p = fast_pow(x_p, d_p, self.key_meta['p'])
            y_q = fast_pow(x_q, d_q, self.key_meta['q'])
            c_p = inverse_mod(self.key_meta['q'], self.key_meta['p'])
            c_q = inverse_mod(self.key_meta['p'], self.key_meta['q'])
            decrypted += chr((self.key_meta['q'] * c_p * y_p + self.key_meta['p'] * c_q * y_q) % self.key_meta['modulus'])

        decrypted_handle = open(decrypted_fn, 'w')
        decrypted_handle.write(decrypted)
        decrypted_handle.close()

        t1 = clock()
        print("Time used:")
        print(t1 - t0)

    # dump to the key file
    def dump(self, filename):
        try:
            from time import clock
            t0 = clock()

            handle = open(filename, 'w')
            pickle.dump(self.key_meta, handle)
            handle.close()

            t1 = clock()
            print("Time used:")
            print(t1 - t0)

        except BaseException as e:
            print e

    # load the key file
    def load(self, filename):
        try:
            handle = open(filename, 'r')
            self.key_meta = dict(pickle.load(handle))
            handle.close()
        except BaseException as e:
            print e

    # print the keys
    def show_keys(self, keys_fn):
        try:
            self.load(keys_fn)
            print self.key_meta
        except BaseException as e:
            print e


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if str(sys.argv[1]) == 'init':
            if len(sys.argv) != 4:
                print 'Invalid number of inputs to init, expects 2, given ' + str(len(sys.argv) - 2)
                print_usage('init')
            else:
                keys = RSA()
                keys.genenerate_keys(str(sys.argv[2]), int(sys.argv[3]))
        elif str(sys.argv[1]) == 'encrypt':
            if len(sys.argv) != 5:
                print 'Invalid number of inputs to encrypt, expects 3, given ' + str(len(sys.argv) - 2)
                print_usage('encrypt')
            else:
                keys = RSA()
                keys.encrypt(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]))
        elif str(sys.argv[1]) == 'decrypt':
            if len(sys.argv) != 5:
                print 'Invalid number of inputs to decrypt, expects 3, given ' + str(len(sys.argv) - 2)
                print_usage('decrypt')
            else:
                keys = RSA()
                keys.decrypt(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]))
        elif str(sys.argv[1]) == 'showkeys':
            if len(sys.argv) != 3:
                print 'Invalid number of inputs to showkeys, expects 1, given ' + str(len(sys.argv) - 2)
            else:
                keys = RSA()
                keys.show_keys(str(sys.argv[2]))
        else:
            print 'Unrecognized input: ' + str(sys.argv[1])
            print_usage()

    else:
        print 'Invalid number of inputs'
        print_usage()