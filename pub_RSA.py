# import pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class KE_RSA:
    __exp_priv_key = None
    __exp_pub_key = None

    def __init__(self):
        rsa = RSA.generate(1024)
        self.__exp_priv_key = rsa.export_key('PEM')
        self.__exp_pub_key = rsa.publickey().exportKey('PEM')
        #print("\npriv_key:", self.__exp_priv_key)
        #print("\npub_key:", self.__exp_pub_key)
    
    
    def encrypt(self, message, exp_pub_key):
        pub_key = PKCS1_OAEP.new( RSA.importKey(exp_pub_key) )
        ct = pub_key.encrypt(message)
        return ct

    def decrypt(self, ciphertext):
        priv_key = PKCS1_OAEP.new( RSA.importKey(self.__exp_priv_key) )
        pt = priv_key.decrypt(ciphertext)
        return pt
        
    def getPublicKey(self):
        return self.__exp_pub_key
# end KE_RSA class


def RSA_test():
    message = b'this is my secret message'
    print('message:', message)
    
    rsa = KE_RSA()
    pub_key = rsa.getPublicKey()
    
    ct = rsa.encrypt(message, pub_key)
    print('\nct:', ct)
    
    pt = rsa.decrypt(ct)
    print('\npt:', pt)
# end RSA_test()

#RSA_test()

