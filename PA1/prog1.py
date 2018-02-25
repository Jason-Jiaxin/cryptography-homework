from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def cbc_encrypt(key, iv, msg):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    byteMsg = bytes(msg, 'utf-8')
    ct = iv

    for i in range(0, len(byteMsg), 16):
        currentBlock = byteMsg[i: i+16]
        prevCBlock = ct[i: i+16]
        ct += encryptor.update(byte_xor(currentBlock, prevCBlock))
    ct = ct[16:]
    return ct

def cbc_decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    msg = byte_xor(decryptor.update(ct[0:16]), iv)

    for i in range(16, len(ct), 16):
        currentBlock = ct[i: i+16]
        prevCBlock = ct[i-16: i]
        msg += byte_xor(decryptor.update(currentBlock), prevCBlock)
    return msg.decode()

def ctr_encrypt(key, ctr, msg):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    byteMsg = bytes(msg, 'utf-8')
    ct = bytes()

    for i in range(0, len(byteMsg), 16):
        msgBlock = byteMsg[i: i+16]
        aesBlock = encryptor.update(ctr)
        ctr = counter_plus_one(ctr)
        ct += byte_xor(msgBlock, aesBlock)
    return ct

def ctr_decrypt(key, ctr, ct):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    msg = bytes()

    for i in range(0, len(ct), 16):
        ctBlock = ct[i: i+16]
        aesBlock = encryptor.update(ctr)
        ctr = counter_plus_one(ctr)
        msg += byte_xor(ctBlock, aesBlock)
    return msg.decode()

def byte_xor(bytes1, bytes2):
    result = bytearray(len(bytes1))
    for i in range(len(bytes1)):
        result[i] = bytes1[i] ^ bytes2[i]
    return bytes(result)

def counter_plus_one(ctr):
    i = int.from_bytes(ctr, byteorder='big')
    i += 1
    return i.to_bytes(16, byteorder='big')

# Padding Oracle attack
key = b'1234567890123456'
iv = b'1234567890123456'
# msg = "1234567890123456" + "1234567890123456" + "abcdefghijklm"
msg = "1234567890123456" + "1234567"
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

def padding_encrypt():
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(bytes(msg, 'utf-8'))
    padded_data += padder.finalize()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text

# c = b'\xd8\xb5\x98H\xc7g\x0c\x94\xb2\x9bT\xd27\x9e.z\xbaFv\x98\x95\x9e\xc5\xbdZ%\x7fiY\xca\x1d<'

def padding_oracle(c):
    try:
        unpadder = padding.PKCS7(128).unpadder()
        msg = unpadder.update(decryptor.update(c)) + unpadder.finalize()
    except ValueError as e:
        # Invalid Padding
        return 0
    # Valid Padding
    return 1

# this changes the ith byte of the second last block of cipher text c
# in order to mess up the decrypted message to cause invalid padding
def change_ith_byte(c, i):
    length = len(c)
    cByteArray = bytearray(c)
    pos = length - 32 + i
    cByteArray[pos] = cByteArray[pos] ^ 255
    return bytes(cByteArray)

# change the last b bytes of the second last block of c to xor padded_msg[i] ^ (b + 1)
# in order to make the decrypted message padded by (b + 1) of last b bytes
def re_pad_c_block(c, b, padded_msg):
    length = len(c)
    cByteArray = bytearray(c)
    for i in range(16 - b, 16):
        cByteArray[length - 32 + i] = cByteArray[length - 32 + i] ^ padded_msg[i] ^ (b + 1)
    return bytes(cByteArray)

# helper function to xor the ith byte of the second last block of c
# try to find a value j s.t. B xor j = b + 1
def set_ith_byte(c, i, j):
    length = len(c)
    cByteArray = bytearray(c)
    pos = length - 32 + i
    cByteArray[pos] = cByteArray[pos] ^ j
    return bytes(cByteArray)

def padding_oracle_attack(c):
    outputFile = open('attack_result.txt', 'w')
    print('Start padding oracle attack')
    outputFile.write('Start padding oracle attack\n')
    print('Original message is:', msg)
    outputFile.write('Original cipher text is: ' + str(msg) + '\n')
    print('Original cipher text is:', c)
    outputFile.write('Original cipher text is: ' + str(c) + '\n')
    L = 16
    numQueries = 0
    # Step 1 get how many bytes were padded
    for i in range(L):
        modifiedC = change_ith_byte(c, i)
        if (padding_oracle(modifiedC) == 0):
            break
    b = L - i
    print('Original padding bytes: ', b)
    outputFile.write('Original padding bytes recovered: ' + str(b) + '\n')
    padded_msg = bytearray(16)
    for i in range(16 - b, 16):
        padded_msg[i] = b

    # Step 2 recover ith byte of the message, from right to left
    for i in range(L-b-1, -1, -1):
        print('Recovering the ' + str(i) + ' byte of the message')
        outputFile.write('Recovering the ' + str(i) + ' byte of the message' + '\n')
        paddingBytes = L-1-i
        preparedC = re_pad_c_block(c, paddingBytes, padded_msg)
        # Try all possible j s.t. B xor j = paddingBytes + 1
        for j in range(256):
            queryC = set_ith_byte(preparedC, i, j)
            outputFile.write('Try j=' + str(j) + '. Query to the oracle: ' + str(queryC) + '\n')
            numQueries += 1
            if (padding_oracle(queryC) == 1):
                break
        print('Succeed at j=' + str(j))
        outputFile.write('Succeed at j=' + str(j) + '\n')
        padded_msg[i] = (paddingBytes + 1) ^ j
        print('The ' + str(i) + 'th byte of the message is: ' + str(padded_msg[i]))
        outputFile.write('The ' + str(i) + 'th byte of the message is: ' + str(padded_msg[i]) + '\n')
    print('The last block of the padded message is:', padded_msg)
    recovered_msg = padded_msg[0:-b]
    print('The recovered last block of the message is:', recovered_msg.decode())
    print('Total number of queries are:', numQueries)
    outputFile.write('The recovered last block of the message is: ' + str(recovered_msg.decode()) + '\n')
    outputFile.write('Total number of queries are: ' + str(numQueries) + '\n')
    outputFile.close()
    return recovered_msg.decode()

c = padding_encrypt()
padding_oracle_attack(c)
