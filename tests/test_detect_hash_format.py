import cryptanalib as ca
from Crypto.Hash import MD5

plaintext = 'foo:bar'

words = ['bar','baz','foo','garply']

hashes = ['4e99e8c12de7e01535248d2bac85e732']

print 'Testing hash format detection...'
if ca.detect_hash_format(words,hashes) != ('foo:bar', 'md5'):
   raise Exception('Hash format detection is broken')
