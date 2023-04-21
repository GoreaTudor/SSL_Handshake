# pip install pycrypto
from Crypto.Cipher import Salsa20
from Crypto import Random


class T_Salsa20:

    def __init__(self):
        pass
    
    @staticmethod
    def generateKey():
        return Random.get_random_bytes(16)
    
    def encrypt(self, message, key):
        nonce = Random.get_random_bytes(8)
        salsa20 = Salsa20.new(key, nonce)
        ct = nonce + salsa20.encrypt(message)
        return ct
    
    def decrypt(self, ciphertext, key):
        ct = ciphertext
        nonce = ct[:8]
        ct = ct[8:]
        salsa20 = Salsa20.new(key, nonce)
        pt = salsa20.decrypt(ct)
        return pt
# end T_Salsa20 class


def Salsa20_test():
    message = b'this is  my secret message'
    key 	= T_Salsa20.generateKey()


    print('message:', message)
    print('len(message):', len(message))

    print('\nkey:', key)
    print('len(key):', len(key))


    salsa20 = T_Salsa20()


    ct = salsa20.encrypt(message, key)
    print('\nct:', ct)

    pt = salsa20.decrypt(ct, key)
    print('\npt:', pt)
# end Salsa20_test()

#Salsa20_test()
