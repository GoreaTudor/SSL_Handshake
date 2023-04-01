# pip install pycrypto
from Crypto.Cipher import AES


message = b'secret message 1' # multiple of 16
key 	= b'1111222233334444'


print('message:', message)
print('len(message):', len(message))

print('key:', key)
print('len(key):', len(key))


cipher = AES.new(key, AES.MODE_ECB)


ct = cipher.encrypt(message)
print('ct:', ct)

pt = cipher.decrypt(ct)
print('pt:', pt)
