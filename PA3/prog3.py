import random, math, hashlib, sys, json
sys.setrecursionlimit(1000000)

# Implement Miller-Rabin Primality test
# Return True if prime, False not prime
def isPrimeMR(N, t):

    def isStrongWitness(a, r, u):
        x = pow(a, u, N)
        if x == 1 or x == N - 1:
            return False
        for i in range(1, r):
            x = pow(x, 2, N)
            if x == N - 1:
                return False
        return True

    if N < 2:
        return False

    if N % 2 == 0:
        return False

    # Decompose N - 1 = 2^r * u
    r = 0
    u = N - 1
    while u % 2 == 0:
        r += 1
        u >>= 1

    for j in range(t):
        a = random.randint(1, N - 1)
        if isStrongWitness(a, r, u):
             return False;
    return True

def getOddNumberOfNBits(n):
    x = random.getrandbits(n-2)
    y = (x << 1) | 1
    return (1 << (n-1)) | y

# Generate prime number of size n bits
def generate_prime(n):
    T = 10
    p = getOddNumberOfNBits(n)
    while not isPrimeMR(p, T):
        p = getOddNumberOfNBits(n)
    return p

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def mulinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

# Return (pk, sk, N)
def generateKey():
    n = 64
    p = generate_prime(n)
    q = generate_prime(n)
    # RSA modulus N = pq
    N = p * q
    phiN = (p - 1) * (q - 1)
    e = random.randint(2, phiN)
    while math.gcd(e, phiN) != 1:
        e = random.randint(2, phiN)
    d = mulinv(e, phiN)
    return (e, d, N)

# Sign a message with private key
# m: message as bytes, sk: private key, N: RSA modulus
# return int
def sign(m, sk, N):
    return pow(bytesToInt(sha256(m)), sk, N)

# Verify the signed message with public key
# m: message as bytes, sigma: signed value of m, pk: public key, N: RSA modulus
# return True or False
def verSign(m, sigma, pk, N):
    y = pow(sigma, pk, N)
    return y == bytesToInt(sha256(m))

def sha256(*args):
    sha = hashlib.sha256()
    for a in args:
        sha.update(a)
    return sha.digest()

def sha256_hex(*args):
    sha = hashlib.sha256()
    for a in args:
        sha.update(a)
    return sha.hexdigest()

def bytesToInt(bytes):
    return int.from_bytes(bytes, byteorder='big')

def intToBytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# Return the binary representation of the hash of salt and x
def hashSX(s, x):
    hex = sha256_hex(intToBytes(s), x)
    binArray = bin(int(hex, base=16))[2:]
    binArray = '0' * (256 - len(binArray)) + binArray
    # print(len(binArray), 'hash', binArray)
    return binArray

# Find a salt s.t. the hash of salt and x starts with n zeros
def solvePuzzle(x, n):
    zeroString = '0' * n
    salt = 1
    while not hashSX(salt, x).startswith(zeroString):
        salt += 1
    return salt

# Verify that the hash of salt and x starts with n zeros
def verPuzzle(s, x, n):
    zeroString = '0' * n
    return hashSX(s, x).startswith(zeroString)

NUM_ZEROS = 10

class Ledger:

    def __init__(self):
        self.userCoins = {}
        self.coinIndex = 1
        self.blocks = []
        self.blockIndex = 0
        self.initTransQueue()

    def createUser(self):
        (pk, sk, N) = generateKey()
        self.userCoins[str(pk)] = set()
        return self.User(pk, sk, N)

    def initLedger(self, user):
        t = self.genTransaction(user, user.pk, self._mintCoins(10), True)
        b = self.Block(self.blockIndex, b'0', [t])
        self.blockIndex += 1
        b.verified = True
        self.blocks.append(b)
        self._processTransactions(b.transactions)

    def initTransQueue(self):
        self.tq = []

    def genTransaction(self, userSend, pkr, coins, isReturn):
        message = bytearray()
        message += bytearray(intToBytes(userSend.pk))
        message += bytearray(intToBytes(pkr))
        for c in coins:
            message += bytearray(intToBytes(c))
        # print('message', message)
        signature = sign(message, userSend.sk, userSend.N)
        transaction = self.Transaction(userSend.pk, userSend.N, pkr, coins, signature)
        if (isReturn):
            return transaction
        else:
            self.tq.append(transaction)

    def genBlock(self, user, T, n):
        trans = []
        while len(self.tq) > 0 and T > 0:
            trans.append(self.tq.pop(0))
            T -= 1
        trans.append(self.genTransaction(user, user.pk, self._mintCoins(10), True))
        b = self.Block(self.blockIndex, self.blocks[-1].blockHash, trans)
        self.blockIndex += 1
        salt = solvePuzzle(b.prevBlockHash + b.blockHash, n)
        b.solution = salt
        self.blocks.append(b)

    def verBlock(self, block, n):
        pass

    def checkBalance(self, pku):
        print('User', pku, 'Num:', len(self.userCoins[str(pku)]), 'Coins:', self.userCoins[str(pku)])

    def userBalance(self):
        print('All user balance')
        for k, v in self.userCoins.items():
            print('User', k, 'Num:', len(v), 'Coins:', v)
        print()

    def _processTransactions(self, transactions):
        for t in transactions:
            if (t.pks == t.pkr):
                self.userCoins[str(t.pkr)].update(t.coins)
            else:
                self.userCoins[str(t.pkr)].update(t.coins)
                self.userCoins[str(t.pks)].difference_update(t.coins)

    def _mintCoins(self, n):
        coins = []
        for i in range(n):
            coins.append(self.coinIndex)
            self.coinIndex += 1
        return coins

    class User:
        def __init__(self, pk, sk, N):
            self.pk = pk
            self.sk = sk
            self.N = N

    class Transaction:
        def __init__(self, pks, N, pkr, coins, signature):
            self.pks = pks
            self.N = N
            self.pkr = pkr
            self.coins = coins
            self.signature = signature

    class Block:
        def __init__(self, index, prevBlockHash, transactions):
            self.index = index
            self.prevBlockHash = prevBlockHash
            self.transactions = transactions
            self.verified = False
            self.solution = 0
            self._calculateHash()

        def _calculateHash(self):
            signatures = [intToBytes(t.signature) for t in self.transactions]
            self.blockHash = sha256(*signatures)

        def printSelf(self):
            print('Block:', self.index, 'Prev block hash:', self.prevBlockHash,
                  'Num transactions', len(self.transactions), 'Block hash:', self.blockHash,
                  'Solution:', self.solution, 'Verified:', self.verified)
