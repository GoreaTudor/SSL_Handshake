# https://github.com/ecies/py
# pip3 install eciespy
from ecies import encrypt, decrypt
from ecies.utils import generate_key


class KE_ECC:
    __exp_priv_key = None
    __exp_pub_key = None

    def __init__(self):
        ecc = generate_key()
        self.__exp_priv_key = ecc.public_key.format(True)
        self.__exp_pub_key = ecc.secret
    
    
    def encrypt(self, message, exp_pub_key):
        # the key must be in bytes
        ct = encrypt(exp_pub_key, message)
        return ct

    def decrypt(self, ciphertext):
        # the key must be in bytes
        pt = decrypt(self.__exp_priv_key, ciphertext)
        return pt
        
    def getPublicKey(self):
        return self.__exp_pub_key
# end KE_ECC class


def ECC_test():
    message = b'this is my secret message'
    print('message:', message)
    
    ecc = KE_ECC()
    pub_key = ecc.getPublicKey()
    
    ct = ecc.encrypt(message, pub_key)
    print('\nct:', ct)
    
    pt = ecc.decrypt(ct)
    print('\npt:', pt)
# end ECC_test()

#ECC_test()

