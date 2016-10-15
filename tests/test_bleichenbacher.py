from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import cryptanalib as ca

ca.queries = 0

# key = RSA.generate(1024, e=3)
# print repr((key.n, key.e, key.d))

(N, e, d) = (151242689083100816738181002620937999512181809379387195583593491291603542900108691523222285405372857139696327669320405999262960106462050217947074001784527818795198802600940780900545580866814212880284349556332186821342122597851846151778484011876082986461493379210023160659498744772656523909821057886586431311599L, 3L, 100828459388733877825454001747291999674787872919591463722395660861069028600072461015481523603581904759797551779546937332841973404308033478631382667856351862771810527368138135852999223344751183054387918163104751737882143190101541038691020249177008890480468119734661689468498909557170851608519691070322297440427L)
key = RSA.construct((N, e, d))
plaintext = '\x02BJ\xe2s^\x1a\x9f\xcfAS\xceGZ\xa0\x99n\xae\x1d;\xd6N\xbb\xf6\xcd\xaf\xb5\'$\x81/0w\xf8\x88"\xb6\xda\xbb\x86\xb6\x9b\xb4z\xde\x04\xd4\xbd\xcf\x17\xe5\xe3G#\x1fv\xabP\x17$015\xb5/il\x12U\xdf0\x1b\xdcEl\x0fQw`\x02#\xd4kQ\x1a/\x89\xfa\x15\x04U\xef>\x90v\xee\x01O\xde\x9d\x0bi\x17\xd1\x16\xe2\x8b\xfa\x087\xb3\x83\x00test plaintext'

ciphertext = key.encrypt(plaintext, 0)[0]

def oracle(ciphertext):
   plaintext = key.decrypt(ciphertext)
   ca.queries += 1
   return plaintext.encode('hex')[:2] == '02'

print 'Testing Bleichenbacher\'s oracle...'

decrypted = ca.bb98_padding_oracle(ciphertext, oracle, key.e, key.n, verbose=True, debug=False) 
print "Plaintext is %r" % key.decrypt(ciphertext)
print "Attack produced plaintext of %r" % (decrypted)
if decrypted != key.decrypt(ciphertext):
   print "Failed with %d queries" % ca.queries   
   raise BleichenbacherAttackFailedError
else:
   print "Succeeded with %d queries" % ca.queries
