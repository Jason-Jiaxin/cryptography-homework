import prog2, random, string

# Test Miller-Rabin implementation for 10 small numbers (size n = 20 bits).
def testMillerRabin():
    print('Miller-Rabin tests begin')
    numTest = 10
    # numAgree = 0
    # numIteration = 10
    for i in range(numTest):
        p = prog2.generate_prime(20)
        isTruelyPrime = prog2.isPrimeNaive(p)
        print('Round:', i, 'Number is:', p, 'Is prime:', isTruelyPrime)
        assert isTruelyPrime == True
    # Another way to test by generating random numbers, and test whether the
    # result of MR prime test and true prime test are same
    # for i in range(numTest):
    #     num = prog2.getOddNumberOfNBits(20)
    #     mrTest = prog2.isPrimeMR(num, numIteration)
    #     truePrimeTest = prog2.isPrimeNaive(num)
    #     print('For number', num, 'is prime:', truePrimeTest, 'Miller-Rabin:', mrTest)
    #     if mrTest == truePrimeTest:
    #         numAgree += 1
    # print('Total tests:', numTest, 'Miller-Rabin output right result:', numAgree)
    print('Miller-Rabin tests finished')
    print()

testMillerRabin()

def testRSA():
    print('RSA tests begin')
    numTest = 10
    rsa = prog2.RSA()
    print('RSA key generated:', 'e:', rsa.e, 'd:', rsa.d)
    for i in range(numTest):
        x = random.randint(1, 100000)
        y = rsa.trapdoor(x)
        decoded = rsa.inverse(y)
        print('Round', i, 'Original message:', x, 'Encoded:', y, 'Decoded:', decoded)
        assert decoded == x
    print('RSA tests finished')
    print()

testRSA()

def getRandomString(n):
    return ''.join(random.choices(string.ascii_uppercase, k=n))

def testMerkleTree():
    print('Merkle Tree tests begin')
    mt = prog2.MerkleTree()
    file_list = [str(x) for x in range(32)]
    print('File list is:', file_list)
    mt.create_tree(file_list)
    print('Tree root is:', mt.root)

    print('read 5 valid files')
    for i in range(5):
        pos = random.randint(0, len(file_list)-1)
        file, siblings_list =  mt.read_file(pos)
        valid = mt.check_integrity(pos, file, siblings_list)
        print('Round', i, 'File is:', file, 'Is valid:', valid)
        assert (file == file_list[pos] and valid == True)

    print('read 5 invalid files')
    for i in range(5):
        pos = random.randint(0, len(file_list)-1)
        file, siblings_list =  mt.read_file(pos)
        alter_file = getRandomString(3)
        valid = mt.check_integrity(pos, alter_file, siblings_list)
        print('Round', i, 'Original File is:', file, 'Altered file is:', alter_file, 'Is valid:', valid)
        assert (valid == False)

    print('write 5 files')
    for i in range(5):
        pos = random.randint(0, len(file_list)-1)
        #Generate new value of file
        new_file = getRandomString(3)
        mt.write_file(pos,new_file)

        # Read file and check integrity
        file, siblings_list =  mt.read_file(pos)
        valid = mt.check_integrity(pos,file,siblings_list)
        print('Round', i, 'New file is:', file, 'Write position is:', pos, 'Is valid:', valid)
        print('Tree root is:', mt.root)
        assert (file == new_file and valid == True)

    print('Merkle Tree tests finished')

testMerkleTree()
