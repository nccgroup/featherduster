import cryptanalib as ca
import feathermodules

def break_alpha_shift(ciphertexts):
   arguments = get_arguments(ciphertexts)
   results = []
   for ciphertext in arguments['ciphertexts']:
      results.append(ca.break_alpha_shift(ciphertext))
   return results

def get_arguments(ciphertexts):
   arguments = {}
   arguments['ciphertexts'] = ciphertexts
   return arguments


feathermodules.module_list['alpha_shift'] = {
   'attack_function':break_alpha_shift,
   'type':'classical',
   'keywords':['alpha'],
   'description':'A brute force attack against an alphabetic shift cipher.'
}
