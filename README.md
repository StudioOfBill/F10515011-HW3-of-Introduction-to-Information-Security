# F10515011-HW3-of-Introduction-to-Information-Security

The usage is referred from the internet, which is the main method and print_usage method. Just type some random command after typing "python rsa.py" and you will be able to see the command.

I wrote a fast_pow using Square & multiply to speed up the pow. However, to be honest, I found it is even slower than the original pow method of Python. I suggest that maybe the original pow method has already used the algorithm I used or some better algorithm which I don't know.

Extended euclidean algorithm is used to find the inverse of e.

The big primes are generated and tested with Miller-Rabin primality test.

The Chinese remainder theorem is used in the decrypting process.

Use "python rsa.py init keys_1024.txt 1024" to initialize a 1024-bit key to keys_1024, and it is the same with 2048 or 4096. Because there can be too much recursion, I set the recursion limit very large, which may cause some problem in certain case. However, it works well on my laptop.

Use "python rsa.py encrypt toy_keys_8.txt Corgi.jpg encrypted.jpg" to encrypt the image with a 8-bit toy key. And use "python rsa.py decrypt toy_keys_8.txt encrypted.jpg decrypted.jpg" to decrypt it. You can also use a larger key, which I've prepared for you already. But it may cost a lot of computation. 