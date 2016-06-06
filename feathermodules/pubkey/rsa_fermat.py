import cryptanalib as ca
import feathermodules
from time import sleep
from Crypto.PublicKey import RSA

def fermat_factor_attack(ciphertexts):
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

      factors = ca.fermat_factor(modulus, minutes=arguments['minutes'], verbose=True)
      if factors[0] != 1:
         answers.append( (modulus, exponent, ca.derive_d_from_pqe(factors[0],factors[1],exponent)) )
   
   for answer in answers:
      key = RSA.construct(answer)
      print "Found private key:\n%s" % key.exportKey()
   
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


feathermodules.module_list['rsa_fermat'] = {
   'attack_function':fermat_factor_attack,
   'type':'pubkey',
   'keywords':['rsa_key'],
   'description':'Use Fermat\'s factorization method to attempt to derive an RSA private key from the public key.',
   'options':{}
}
