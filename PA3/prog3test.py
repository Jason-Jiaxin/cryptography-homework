import prog3, random, string
from timeit import default_timer as timer

def getRandomString(n):
    return ''.join(random.choices(string.ascii_uppercase, k=n))

def testRSASign():
    print('RSA signature tests begin')
    numTest = 5
    (pk, sk, N) = prog3.generateKey()
    for i in range(numTest):
        m = getRandomString(5).encode()
        sigma = prog3.sign(m, sk, N)
        isCorrect = prog3.verSign(m, sigma, pk, N)
        print('Round:', i, 'Message is:', m, 'Verify correct:', isCorrect, 'Message hash:', sigma)
        assert isCorrect == True

# testRSASign()

def testPoW():
    print('Proof of Work tests begin')
    numTest = 2
    for n in range(5, 26, 5):
        print('Hash starts with', n, 'zeros')
        start = timer()
        for i in range(numTest):
            m = getRandomString(5).encode()
            salt = prog3.solvePuzzle(m, n)
            assert prog3.verPuzzle(salt, m, n) == True
            print('Round:', i, 'Message is:', m, 'Salt is', salt, 'Message hash:', prog3.hashSX(salt, m))
        end = timer()
        print('Total time for', numTest, 'hashes', end - start)
        print()

# testPoW()
