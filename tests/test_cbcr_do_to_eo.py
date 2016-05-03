import cryptanalib as ca
from Crypto.Cipher import AES
from Crypto import Random

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)

def my_decryption_oracle(ciphertext):
   plaintext = cipher.decrypt(ciphertext)
   return ca.pkcs7_padding_remove(plaintext,AES.block_size)

def my_padding_oracle(ciphertext):
   plaintext = cipher.decrypt(ciphertext)
   return ca.pkcs7_padding_remove(plaintext,AES.block_size) != False

new_plaintext = 'I am the very model of a modern major-general.'

print 'Testing CBC-R functionality...'
print 'Reversing decryption oracle:'
new_ciphertext = ca.cbcr(new_plaintext, my_decryption_oracle, block_size=AES.block_size)
print 'New ciphertext is %s' % new_ciphertext.encode('hex')
cipher = AES.new(key, AES.MODE_CBC, iv)
print 'New plaintext is %s' % ca.pkcs7_padding_remove(cipher.decrypt(new_ciphertext), AES.block_size)
print 'Reversing padding oracle:'
new_ciphertext = ca.cbcr(new_plaintext, my_padding_oracle,is_padding_oracle=True, block_size=AES.block_size)
print 'New ciphertext is %s' % new_ciphertext.encode('hex')
cipher = AES.new(key, AES.MODE_CBC, iv)
print 'New plaintext is %s' % ca.pkcs7_padding_remove(cipher.decrypt(new_ciphertext), AES.block_size)

if raw_input('Did this decrypt correctly (yes)?').lower() not in ['y','yes','']:
   raise Exception('CBCR failed.')
