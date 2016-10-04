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

print 'Testing CBC-R functionality with plain decryption oracle...'
new_ciphertext = ca.cbcr(new_plaintext, my_decryption_oracle, block_size=AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
cbcr_plaintext = ca.pkcs7_padding_remove(cipher.decrypt(new_ciphertext), AES.block_size)
try:
   assert(cbcr_plaintext[16:] == new_plaintext) 
except:
   exit("CBCR functionality is broken with plain decryption oracles.")

print 'Testing CBC-R functionality with padding oracle...'
new_ciphertext = ca.cbcr(new_plaintext, my_padding_oracle, is_padding_oracle=True, block_size=AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
cbcr_plaintext = ca.pkcs7_padding_remove(cipher.decrypt(new_ciphertext), AES.block_size)
try:
   assert(cbcr_plaintext[16:] == new_plaintext) 
except:
   exit("CBCR functionality is broken with padding oracles.")

