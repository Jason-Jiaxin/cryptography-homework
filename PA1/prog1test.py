import os, random, string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import prog1

key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
msg = "1234567890123456" + "abcdefghijklmnop"

##################### CBC #####################
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
cipher_text = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()
cipher_text_prog1 = prog1.cbc_encrypt(key, iv, msg)

assert cipher_text == cipher_text_prog1

decipher_text = decryptor.update(cipher_text).decode()
decipher_text_prog1 = prog1.cbc_decrypt(key, iv, cipher_text_prog1)

assert decipher_text == msg and decipher_text == decipher_text_prog1


#################### CTR #####################
cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
cipher_text = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()
cipher_text_prog1 = prog1.ctr_encrypt(key, ctr, msg)

assert cipher_text == cipher_text_prog1

decipher_text = decryptor.update(cipher_text).decode()
decipher_text_prog1 = prog1.ctr_decrypt(key, ctr, cipher_text_prog1)

assert decipher_text == msg and decipher_text == decipher_text_prog1

# Wrap library functions to simplify the call
def lib_cbc_encrypt(key, iv, msg):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()
    return cipher_text

def lib_cbc_decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    msg = decryptor.update(ct).decode()
    return msg

def lib_ctr_encrypt(key, ctr, msg):
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()
    return cipher_text

def lib_ctr_decrypt(key, ctr, ct):
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
    decryptor = cipher.decryptor()
    msg = decryptor.update(ct).decode()
    return msg

# gererate a random alphanumeric string of length multiple of 16
def rand_message():
    x = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(random.randrange(16, 256, 16)))
    return x

# test ten random key and message.
# assert the encrypted messages are the same using library and my own implementation.
# assert the decrypted messages are the same, and same as the original message
def test10():
    for i in range(10):
        key = os.urandom(16)
        iv = os.urandom(16)
        ctr = os.urandom(16)
        msg = rand_message()
        # print (msg)

        # CBC Mode
        ct_cbc_lib = lib_cbc_encrypt(key, iv, msg)
        ct_cbc_prog1 = prog1.cbc_encrypt(key, iv, msg)
        assert ct_cbc_lib == ct_cbc_prog1
        dt_cbc_lib = lib_cbc_decrypt(key, iv, ct_cbc_lib)
        dt_cbc_prog1 = prog1.cbc_decrypt(key, iv, ct_cbc_prog1)
        assert dt_cbc_lib == msg and dt_cbc_lib == dt_cbc_prog1

        # CTR Mode
        ct_ctr_lib = lib_ctr_encrypt(key, ctr, msg)
        ct_ctr_prog1 = prog1.ctr_encrypt(key, ctr, msg)
        assert ct_ctr_lib == ct_ctr_prog1
        dt_ctr_lib = lib_ctr_decrypt(key, ctr, ct_ctr_lib)
        dt_ctr_prog1 = prog1.ctr_decrypt(key, ctr, ct_ctr_prog1)
        assert dt_ctr_lib == msg and dt_ctr_lib == dt_ctr_prog1

test10()
