# pip install pycrypto
from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack


class T_Blowfish:
    __bs = None

    def __init__(self):
        self.__bs = Blowfish.block_size
    
    @staticmethod
    def generateKey():
        return Random.get_random_bytes(16)
    
    def encrypt(self, message, key):
        iv = Random.new().read(self.__bs)
        blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plen = self.__bs - divmod(len(message),self.__bs)[1]
        padding = [plen]*plen
        padding = pack('b'*plen, *padding)
        ct = iv + blowfish.encrypt(message + padding)
        return ct
    
    def decrypt(self, ciphertext, key):
        ct = ciphertext
        iv = ct[:self.__bs]
        ct = ct[self.__bs:]
        blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        pt = blowfish.decrypt(ct)
        last_byte = pt[-1]
        pt = pt[:- (last_byte if type(last_byte) is int else ord(last_byte))]
        return pt
# end T_Blowfish class


def Blowfish_test():
    message = b'this is  my secret message'
    key 	= T_Blowfish.generateKey()


    print('message:', message)
    print('len(message):', len(message))

    print('\nkey:', key)
    print('len(key):', len(key))


    blowfish = T_Blowfish()


    ct = blowfish.encrypt(message, key)
    print('\nct:', ct)

    pt = blowfish.decrypt(ct, key)
    print('\npt:', pt)
# end Blowfish_test()

#Blowfish_test()
