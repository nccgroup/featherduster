from Crypto import Random
from Crypto.Cipher import AES
import cryptanalib as ca
from zlib import compress

plaintext = 'I am the very model of a modern major-general, I\'ve information vegetable, animal and mineral, I know the kings of England and I quote the fights historical, from Marathon to Waterloo in order categoricalAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

plaintext2 = 'I am the very model of a modern major-general, I\'m covered in bees and I have information vegetable, animal and mineral, I know the kings of England and I quote the fights historical, from Marathon to Waterloo in order categoricalAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)

two_time_pad_key = Random.new().read(len(plaintext2))

ecb_cipher = AES.new(key, AES.MODE_ECB, iv)
ecb_ciphertexts = [ecb_cipher.encrypt(ca.pkcs7_pad(plaintext, AES.block_size))]
ecb_cipher = AES.new(key, AES.MODE_ECB, iv)
ecb_ciphertexts.append(ecb_cipher.encrypt(ca.pkcs7_pad(plaintext2,AES.block_size)))
print 'ECB ciphertexts are:'
print "\n".join([ct.encode('hex') for ct in ecb_ciphertexts])

cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ciphertexts = [cbc_cipher.encrypt(ca.pkcs7_pad(plaintext,AES.block_size))]
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ciphertexts.append(cbc_cipher.encrypt(ca.pkcs7_pad(plaintext2,AES.block_size)))
print 'CBC fixed IV ciphertexts are:'
print "\n".join([ct.encode('hex') for ct in cbc_ciphertexts])

mb_xor_ciphertexts = [ca.sxor(plaintext,"\xfa\x4e\x77\x01\x43"*len(plaintext))]
mb_xor_ciphertexts.append(ca.sxor(plaintext2,"\xfa\x4e\x77\x01\x43"*len(plaintext2)))
print 'Multi-byte XOR ciphertexts are:'
print "\n".join([ct.encode('hex') for ct in mb_xor_ciphertexts])

two_time_pad_ciphertexts = [ca.sxor(plaintext,two_time_pad_key)]
two_time_pad_ciphertexts.append(ca.sxor(plaintext2,two_time_pad_key))
print 'Two-time pad ciphertexts are:'
print "\n".join([ct.encode('hex') for ct in two_time_pad_ciphertexts])

compressed_messages = [compress(plaintext), compress(plaintext2)]

print 'Analyzing ECB ciphertexts...'
ca.analyze_ciphertext(ecb_ciphertexts,verbose=True)
print ''
print 'Analyzing CBC fixed-IV ciphertexts...'
ca.analyze_ciphertext(cbc_ciphertexts,verbose=True)
print ''
print 'Analyzing multi-byte XOR ciphertexts...'
ca.analyze_ciphertext(mb_xor_ciphertexts,verbose=True)
print ''
print 'Analyzing two-time pad ciphertexts...'
ca.analyze_ciphertext(two_time_pad_ciphertexts,verbose=True)
print ''
print 'Analyzing hex-encoded ciphertext...'
ca.analyze_ciphertext([ct.encode('hex') for ct in ecb_ciphertexts],verbose=True)
print ''
print 'Analyzing base64-encoded ciphertext...'
ca.analyze_ciphertext([ct.encode('base64') for ct in ecb_ciphertexts],verbose=True)
print ''
print 'Analyzing compressed plaintexts...'
ca.analyze_ciphertext(compressed_messages,verbose=True)

if raw_input('Were the ciphertexts properly identified (yes)?').lower() not in ['y','yes','']:
   raise Exception('Ciphertext analysis is broken.')
