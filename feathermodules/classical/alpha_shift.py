import cryptanalib as ca
import feathermodules

def break_alpha_shift(ciphertexts):
   results = []
   for ciphertext in ciphertexts:
      results.append(ca.break_alpha_shift(ciphertext))
   return results


feathermodules.module_list['alpha_shift'] = {
   'attack_function':break_alpha_shift,
   'type':'classical',
   'keywords':['alpha', 'classical', 'individually_low_entropy'],
   'description':'A brute force attack against an alphabetic shift cipher.',
   'options': {}
}
