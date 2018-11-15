from Crypto import Random
from Crypto.Cipher import AES
import cryptanalib as ca
from zlib import compress, decompress
from urllib import quote

print 'Testing ciphertext analysis engine...'

plaintext = 'I am the very model of a modern major-general, I\'ve information vegetable, animal and mineral, I know the kings of England and I quote the fights historical, from Marathon to Waterloo in order categoricalAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

plaintext2 = 'I am the very model of a modern major-general, I\'m covered in bees and I have information vegetable, animal and mineral, I know the kings of England and I quote the fights historical, from Marathon to Waterloo in order categoricalAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

RSA_pubkey_critically_small_n = """-----BEGIN PUBLIC KEY-----
MDswDQYJKoZIhvcNAQEBBQADKgAwJwIgM+SdTJtjCuCzjqr34+02DsEEp8TOuDOq
2nznVqc7g1ECAwEAAQ==
-----END PUBLIC KEY-----
"""

RSA_pubkey_very_small_n = """
-----BEGIN PUBLIC KEY-----
MHswDQYJKoZIhvcNAQEBBQADagAwZwJgWDO0D6tHeBPEkKwen2U0wKbBMyCEEiBe
0hNIBaG7YEMKAGCX48e22xzkTT4gmtErVgGvfkWzKW/PpWOMxQcH0u/DyR6fFFZf
ntsJZBoKZYk2sVxLjpl/fOR567JNWDlHAgMBAAE=
-----END PUBLIC KEY-----
"""

RSA_pubkey_small_n = """
-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgBJut++Q7fjnrCzax5d8fuJIux4u
l7bRrm9Il5iYmwE1JSkTUITtSXnGfAA4+H5kPTnv6D7KR3ii0IuKicAQStOsof/s
7ul3etw72y+v1BMZhj92cq/+ZdaLbhLVkhMlwreuuzPxui7Y7wQXhIJCf20TS/zE
oZGmi6usbfkw3G19AgMBAAE=
-----END PUBLIC KEY-----
"""

key = b'YELLOW SUBMARINE'
iv = Random.new().read(AES.block_size)

two_time_pad_key = Random.new().read(len(plaintext2))

ecb_cipher = AES.new(key, AES.MODE_ECB, iv)
ecb_ciphertexts = [ecb_cipher.encrypt(ca.pkcs7_pad(plaintext, AES.block_size))]
ecb_cipher = AES.new(key, AES.MODE_ECB, iv)
ecb_ciphertexts.append(ecb_cipher.encrypt(ca.pkcs7_pad(plaintext2,AES.block_size)))

cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ciphertexts = [cbc_cipher.encrypt(ca.pkcs7_pad(plaintext,AES.block_size))]
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ciphertexts.append(cbc_cipher.encrypt(ca.pkcs7_pad(plaintext2,AES.block_size)))

mb_xor_ciphertexts = [ca.sxor(plaintext,"\xfa\x4e\x77\x01\x43"*len(plaintext))]
mb_xor_ciphertexts.append(ca.sxor(plaintext2,"\xfa\x4e\x77\x01\x43"*len(plaintext2)))

two_time_pad_ciphertexts = [ca.sxor(plaintext,two_time_pad_key)]
two_time_pad_ciphertexts.append(ca.sxor(plaintext2,two_time_pad_key))

compressed_messages = [compress(plaintext), compress(plaintext2)]

print 'Analyzing ECB ciphertexts...'
ecb_results = ca.analyze_ciphertext(ecb_ciphertexts)
if 'ecb' not in ecb_results['keywords']:
   exit('ECB detection is broken.')

print 'Analyzing CBC fixed-IV ciphertexts...'
cbc_results = ca.analyze_ciphertext(cbc_ciphertexts)
if 'cbc_fixed_iv' not in cbc_results['keywords']:
   exit('CBC fixed IV detection is broken.')

print 'Analyzing multi-byte XOR ciphertexts...'
multi_byte_xor_results = ca.analyze_ciphertext(mb_xor_ciphertexts)
if 'individually_low_entropy' not in multi_byte_xor_results['keywords']:
   exit('Multi-byte XOR not flagged as weak crypto.')

print 'Analyzing two-time pad ciphertexts...'
two_time_pad_results = ca.analyze_ciphertext(two_time_pad_ciphertexts)
if 'key_reuse' not in two_time_pad_results['keywords']:
   exit('Key reuse detection is broken.')

print 'Analyzing hex-encoded ciphertext...'
hex_results = ca.analyze_ciphertext([ct.encode('hex') for ct in ecb_ciphertexts])
if hex_results['decoded_ciphertexts'][0] != ecb_ciphertexts[0]:
   exit('Hex encoding detection is broken.')

print 'Analyzing base64-encoded ciphertext...'
base64_results = ca.analyze_ciphertext([ct.encode('base64') for ct in ecb_ciphertexts])
if base64_results['decoded_ciphertexts'][0] != ecb_ciphertexts[0]:
   exit('Base64 encoding detection is broken.')

print 'Analyzing url-encoded ciphertext...'
url_results = ca.analyze_ciphertext([quote(ct) for ct in ecb_ciphertexts])
if url_results['decoded_ciphertexts'][0] != ecb_ciphertexts[0]:
   exit('URL encoding detection is broken.')

print 'Analyzing compressed plaintexts...'
compressed_results = ca.analyze_ciphertext(compressed_messages)
if compressed_results['decoded_ciphertexts'][0] != decompress(compressed_messages[0]):
   exit('Zlib compression detection is broken.')

print 'Analyzing critically small RSA key...'
crit_rsa_length_results = ca.analyze_ciphertext([RSA_pubkey_critically_small_n])
if 'rsa_small_n' not in crit_rsa_length_results['keywords']:
   exit('Small RSA modulus detection is broken.')

print 'Analyzing very small RSA key...'
very_small_rsa_length_results = ca.analyze_ciphertext([RSA_pubkey_very_small_n])
if 'rsa_small_n' not in very_small_rsa_length_results['keywords']:
   exit('Small RSA modulus detection is broken.')

print 'Analyzing small RSA key...'
small_rsa_length_results = ca.analyze_ciphertext([RSA_pubkey_small_n])
if 'rsa_small_n' not in small_rsa_length_results['keywords']:
   exit('Small RSA modulus detection is broken.')

