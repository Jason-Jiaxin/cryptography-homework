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
    print()
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

NUM_ZEROS = 10

def testBlockChain():
    print('Block chain tests begin')
    l = prog3.Ledger()
    u1 = l.createUser()
    u2 = l.createUser()
    u3 = l.createUser()
    l.initLedger(u1)
    l.printAllBlocks()
    l.userBalance()
    print('Test: Valid transaction')
    l.genTransaction(u1, u2.pk, [1, 2], False)
    l.genTransaction(u1, u3.pk, [4, 5, 6], False)
    l.genBlock(u2, 2, NUM_ZEROS)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    print('Test: Invalid transaction: User try to send coins he not own')
    l.genTransaction(u1, u2.pk, [7], False)
    l.genTransaction(u1, u3.pk, [3, 11], False)
    l.genBlock(u1, 2, NUM_ZEROS)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    print('Test: Invalid transaction: User try to double spend')
    l.genTransaction(u1, u2.pk, [3], False)
    l.genTransaction(u1, u3.pk, [3], False)
    l.genBlock(u1, 3, NUM_ZEROS)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    print('Test: Invalid transaction: User try to modify the receiver of a valid transaction')
    l.genTransaction(u1, u2.pk, [8], False)
    l.tq[-1].pkr = u3.pk
    l.genBlock(u3, 3, NUM_ZEROS)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    print('Test: Invalid transaction: User try to change transactions in a valid block')
    l.genBlock(u1, 2, NUM_ZEROS)
    l.blocks[-1].transactions[-1] = l.genTransaction(u3, u3.pk, l._mintCoins(10), True)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    print('Test: Valid transaction: Process remaining transactions in the queue')
    l.genBlock(u1, 2, NUM_ZEROS)
    l.verBlock()
    l.printAllBlocks()
    l.printTQ()
    l.userBalance()

    # (isValid, validTrans) = l._verTransactions(l.blocks[-1].transactions)
    # print(isValid)
    # for t in validTrans:
    #     print(t)

testRSASign()
testBlockChain()
testPoW()
