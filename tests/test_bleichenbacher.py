from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import cryptanalib as ca

ca.queries = 0

key = RSA.generate(1024)
plaintext = 'test plaintext'
cipher = PKCS1_v1_5.new(key)

ciphertext = cipher.encrypt(plaintext)

def oracle(ciphertext):
   plaintext = key.decrypt(ciphertext)
   ca.queries += 1
   return plaintext.encode('hex')[:2] == '02'

print 'Testing Bleichenbacher\'s oracle...'

decrypted = ca.bb98_padding_oracle(ciphertext, oracle, key.e, key.n, verbose=True, debug=False) 
print "Attack produced plaintext of %r" % (decrypted)
if decrypted != key.decrypt(ciphertext):
   print "Failed with %d queries" % ca.queries   
   raise BleichenbacherAttackFailedError
else:
   print "Succeeded with %d queries" % ca.queries
