# import pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


message = b'this is my secret message'
print('message:\n', message)


rsa = RSA.generate(1024)

exp_priv_key = rsa.export_key('PEM'); print('\nexp priv key:\n', exp_priv_key)
exp_pub_key = rsa.publickey().exportKey('PEM'); print('\nexp pub key:\n', exp_pub_key)


pub_key = PKCS1_OAEP.new( RSA.importKey(exp_pub_key) )

ct = pub_key.encrypt(message)
print('\nct:\n', ct)


priv_key = PKCS1_OAEP.new( RSA.importKey(exp_priv_key) )

pt = priv_key.decrypt(ct)
print('\npt:\n', pt)

