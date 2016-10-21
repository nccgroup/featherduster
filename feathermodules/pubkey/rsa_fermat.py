import cryptanalib as ca
import feathermodules
from time import sleep
from Crypto.PublicKey import RSA

def fermat_factor_attack(ciphertexts):
   options = dict(feathermodules.current_options)
   options = prepare_options(options, ciphertexts)
   if options == False:
      print '[*] Could not process options.'
      return False
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

      factors = ca.fermat_factor(modulus, minutes=options['minutes_to_wait'], verbose=True)
      if factors[0] != 1:
         answers.append( (modulus, exponent, ca.derive_d_from_pqe(factors[0],factors[1],exponent)) )
   
   for answer in answers:
      key = RSA.construct(answer)
      print "Found private key:\n%s" % key.exportKey()
   
   if len(answers) == 0:
      return False
   else:
      return ['N:{},e:{},d:{}'.format(answer) for answer in answers]

      

def prepare_options(options, ciphertexts):
   try:
      options['minutes_to_wait'] = float(options['minutes_to_wait'])
   except:
      print '[*] Couldn\'t convert minutes provided to a number.'
      return False
   return options


feathermodules.module_list['rsa_fermat'] = {
   'attack_function':fermat_factor_attack,
   'type':'pubkey',
   'keywords':['rsa_key'],
   'description':'Use Fermat\'s factorization method to attempt to derive an RSA private key from the public key.',
   'options':{
      'minutes_to_wait': '0.5'
   }
}
