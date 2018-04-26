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
pk = 24824973012987653108813315472142148812868167137203560813408237508995350164639
sk = 55681588644576920927153194286920066383164290810445193335097792020100461327855
N = 81711360432909513721989947016618208086222908053157068342007920422176201253541
NUM_ZEROS = 10

def testBlockChain():
    l = prog3.Ledger()
    # u = l.User(pk, sk, N)
    u1 = l.createUser()
    u2 = l.createUser()
    u3 = l.createUser()
    # print(type(u.pk), prog3.intToBytes(u.pk))
    # t = l.genTransaction(u, u.pk, l._mintCoins(10))
    # print(t.coins)
    # print(t.signature)
    # b = l.Block(1, 0, [t])
    # print(b.blockHash)
    l.initLedger(u1)
    l.userBalance()
    l.genTransaction(u1, u2.pk, [1, 2], False)
    l.genTransaction(u1, u3.pk, [5, 6], False)
    l.genBlock(u2, 2, NUM_ZEROS)
    l.blocks[-1].printSelf()

testBlockChain()
