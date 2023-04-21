# pip install pycrypto
from Crypto.Cipher import CAST
from Crypto import Random


class T_CAST:
    __bs = None

    def __init__(self):
        self.__bs = CAST.block_size
    
    @staticmethod
    def generateKey():
        return Random.get_random_bytes(16)
    
    def encrypt(self, message, key):
        cast = CAST.new(key, CAST.MODE_OPENPGP)
        ct = cast.encrypt(message)
        return ct
    
    def decrypt(self, ciphertext, key):
        ct = ciphertext
        eiv = ct[:self.__bs+2]
        ct = ct[self.__bs+2:]
        cast = CAST.new(key, CAST.MODE_OPENPGP, eiv)
        pt = cast.decrypt(ct)
        return pt
# end T_CAST class


def CAST_test():
    message = b'this is  my secret message'
    key 	= T_CAST.generateKey()


    print('message:', message)
    print('len(message):', len(message))

    print('\nkey:', key)
    print('len(key):', len(key))


    cast = T_CAST()


    ct = cast.encrypt(message, key)
    print('\nct:', ct)

    pt = cast.decrypt(ct, key)
    print('\npt:', pt)
# end CAST_test()

#CAST_test()
