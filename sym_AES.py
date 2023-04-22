# pip install pycrypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class T_AES:
    __aes = None

    def __init__(self):
        pass
    
    @staticmethod
    def generateKey():
        return get_random_bytes(16)
    
    def encrypt(self, message, key):
        self.__aes = AES.new(key, AES.MODE_ECB)
        pt = list(message)
        while len(pt) % 16 != 0:  # padding
            pt.append(0)
        ct = self.__aes.encrypt( bytes(''.join([chr(x) for x in pt]), 'UTF-8') )
        return ct
    
    def decrypt(self, ciphertext, key):
        self.__aes = AES.new(key, AES.MODE_ECB)
        pt = list( self.__aes.decrypt(ciphertext) )
        pt = [x for x in pt if x != 0]  # remove padding
        return bytes(''.join([chr(x) for x in pt]), 'UTF-8')
# end T_AES class


def AES_test():
    message = b'this is  my secret message'
    key 	= T_AES.generateKey()


    print('message:', message)
    print('len(message):', len(message))

    print('\nkey:', key)
    print('len(key):', len(key))


    aes = T_AES()


    ct = aes.encrypt(message, key)
    print('\nct:', ct)

    pt = aes.decrypt(ct, key)
    print('\npt:', pt)
# end AES_test()

#AES_test()
