import cryptanalib as ca
from Crypto.Cipher import AES
from Crypto import Random

key = iv = Random.new().read(AES.block_size)

cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
second_cipher_because_yolo = AES.new(key, mode=AES.MODE_CBC, IV=iv)

ciphertext = cipher.encrypt(ca.pkcs7_pad('Check out the mic while the DJ revolves it (ICE ICE BABY)',AES.block_size))

def decryption_oracle(ciphertext):
   return second_cipher_because_yolo.decrypt(ciphertext)

print 'Key and IV are %s and %s' % (key.encode('hex'), iv.encode('hex'))
retrieved_iv = ca.retrieve_iv(decryption_oracle, ciphertext, AES.block_size)
print 'Ciphertext is %s' % ciphertext.encode('hex')
plaintext = decryption_oracle(ciphertext)
print 'Produced plaintext is %s' % plaintext.encode('hex')
print 'First block of produced plaintext is %s' % plaintext[:AES.block_size].encode('hex')
print 'Second block of produced plaintext is %s' % plaintext[AES.block_size:AES.block_size*2].encode('hex')
print 'Retrieved IV is %s' % retrieved_iv.encode('hex')

if iv != retrieved_iv:
   raise Exception('Decryption oracle IV retrieval is broken')

