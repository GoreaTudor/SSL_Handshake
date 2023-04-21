# pip install pycrypto
from Crypto.Cipher import ARC2
from Crypto import Random


class T_ARC2:
    __bs = None

    def __init__(self):
        self.__bs = ARC2.block_size
    
    @staticmethod
    def generateKey():
        return Random.get_random_bytes(16)
    
    def encrypt(self, message, key):
        iv = Random.new().read(self.__bs)
        arc2 = ARC2.new(key, ARC2.MODE_CFB, iv)
        ct = iv + arc2.encrypt(message)
        return ct
    
    def decrypt(self, ciphertext, key):
        ct = ciphertext
        iv = ct[:self.__bs]
        ct = ct[self.__bs:]
        arc2 = ARC2.new(key, ARC2.MODE_CFB, iv)
        pt = arc2.decrypt(ct)
        return pt
# end T_ARC2 class


def ARC2_test():
    message = b'this is  my secret message'
    key 	= T_ARC2.generateKey()


    print('message:', message)
    print('len(message):', len(message))

    print('\nkey:', key)
    print('len(key):', len(key))


    arc2 = T_ARC2()


    ct = arc2.encrypt(message, key)
    print('\nct:', ct)

    pt = arc2.decrypt(ct, key)
    print('\npt:', pt)
# end ARC2_test()

#ARC2_test()
