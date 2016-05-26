import cryptanalib as ca
import feathermodules
from Crypto.PublicKey import RSA

def wiener_attack(ciphertexts):
   arguments = get_arguments(ciphertexts)
   answers = []
   for ciphertext in ciphertexts:
      try:
         key = RSA.importKey(ciphertext)
         if key.has_private():
            continue
         else:
            modulus = key.n
            exponent = key.e
      except:
         continue

      p = ca.wiener(modulus, exponent, minutes=arguments['minutes'], verbose=True)
      answers.append((modulus, exponent, p))
   
   for n, e, p in answers:
      try:
         d = ca.derive_d_from_pqe(p, n/p, e)
         key = RSA.construct((n, e, d))
         print "Found private key:\n%s" % key.exportKey()
      except:
         print "\nAttack failed, key is too strong."
   
   return ''

      

def get_arguments(ciphertexts):
   arguments = {}
   arguments['ciphertexts'] = ciphertexts
   while True:
      minutes = raw_input('Please input the number of minutes you\'re willing to wait for each factorization to complete (fractional minutes are accepted): ')
      try:
         arguments['minutes'] = float(minutes)
         break
      except ValueError:
         print "Sorry, I couldn't turn that into a number. Please try again."
     
   return arguments


feathermodules.module_list['rsa_wiener'] = {
   'attack_function':wiener_attack,
   'type':'pubkey',
   'keywords':['rsa_key'],
   'description':'Use Wiener\'s attack on weak RSA keys to attempt to derive an a private key from its public key.'
}
