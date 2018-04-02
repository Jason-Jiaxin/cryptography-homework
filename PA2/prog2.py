import random, math, hashlib

# Implement Miller-Rabin Primality test
# Return 1 if prime, 0 not prime
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

# primality test using the naive approach
def isPrimeNaive(p):
    if p % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(p))+2, 2):
        if p % i == 0:
            return False
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

############## Problem 1 b ##############

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return False
    else:
        return x % m

class RSA:
	# initialize RSA, generate e, d
    def __init__(self):
        self.gen()

	# Use generate_prime
    def gen(self):
		# security parameter
        self.n = 1024

		# Primes p and q
        self.p = generate_prime(self.n)
        self.q = generate_prime(self.n)

		# RSA modulus N = pq
        self.rsamodulus = self.p * self.q
        self.phiN = (self.p - 1) * (self.q - 1)

		# Public key e
        e = self.genE()
        d = modinv(e, self.phiN)
        # print('e', e, 'd', d)
        while not d:
            # print('e', e, 'd', d)
            e = self.genE()
            d = modinv(e, self.phiN)

        self.e = e

		# Secret key d
        self.d = d

    def trapdoor(self, x):
        return pow(x, self.e, self.rsamodulus)

    def inverse(self, y):
        return pow(y, self.d, self.rsamodulus)

    def genE(self):

        size_e = 1024
        e = getOddNumberOfNBits(size_e)
        # e = random.randint(3, self.phiN)
        while math.gcd(e, self.phiN) != 1:
            # print(e)
            e = getOddNumberOfNBits(size_e)
            # e = random.randint(3, self.phiN)
        return e

def sha256(*args):
    sha = hashlib.sha256()
    for a in args:
        sha.update(a)
    return sha.digest()

class MerkleTree:
    def __init__(self):
        self.n = 0
        self.file_list = []
        self.hashArray = []
        self.root = 0

    def create_tree(self, file_list):
        self.n = len(file_list)
        self.file_list = file_list
        self._create_tree(file_list)

    def read_file(self, i):
        return (self.file_list[i], self._get_sibling_list(i))

    def write_file(self, i, file):
        self.file_list[i] = file
        self._update_hash(i, file)

    def check_integrity(self, i, file, siblings_list):
        computed_root = self._compute_root(i, file, siblings_list)
        return computed_root == self.root

    def _create_tree(self, file_list):
        hashList = []
        size = len(file_list)
        for f in file_list:
            hashList.append(sha256(f.encode()))
            # print(hashValue)

        while size > 1:
            tempList = []
            for i in range(0, size, 2):
                hashValue = sha256(hashList[i], hashList[i+1])
                # print(hashValue)
                tempList.append(hashValue)
            hashList = tempList + hashList
            size = int(size/2)
        hashList.insert(0, b'dummy')
        self.hashArray = hashList
        self.root = hashList[1]
        # print(len(hashList))
        # print(hashList)

    def _get_sibling_list(self, i):
        result = []
        pos = len(self.hashArray) - (self.n - i)
        while pos > 1:
            if pos % 2 == 0:
                result.append(self.hashArray[pos+1])
            else:
                result.append(self.hashArray[pos-1])
            pos = int(pos/2)
        return result

    def _update_hash(self, i, file):
        pos = len(self.hashArray) - (self.n - i)
        self.hashArray[pos] = sha256(file.encode())
        pos = int(pos/2)
        while pos >= 1:
            self.hashArray[pos] = sha256(self.hashArray[pos*2], self.hashArray[pos*2+1])
            pos = int(pos/2)
        self.root = self.hashArray[1]

    def _compute_root(self, i, file, siblings_list):
        hashValue = sha256(file.encode())
        pos = len(self.hashArray) - (self.n - i)
        i = 0
        while pos > 1:
            if pos % 2 == 0:
                hashValue = sha256(hashValue, siblings_list[i])
            else:
                hashValue = sha256(siblings_list[i], hashValue)
            pos = int(pos/2)
            i += 1
        return hashValue
