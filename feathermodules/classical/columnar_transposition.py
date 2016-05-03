import cryptanalib as ca
import feathermodules

def break_columnar_transposition(ciphertexts):
   arguments = get_arguments(ciphertexts)
   results = []
   for ciphertext in arguments['ciphertexts']:
      results.append(ca.break_columnar_transposition(ciphertext, num_answers=arguments['num_answers']))
   return results

def get_arguments(ciphertexts):
   arguments = {}
   arguments['num_answers'] = int(raw_input('How many candidate answers would you like per ciphertext? '))
   arguments['ciphertexts'] = ciphertexts
   return arguments


feathermodules.module_list['column_trans'] = {
   'attack_function':break_columnar_transposition,
   'type':'classical',
   'keywords':['transposition'],
   'description':'A brute force attack against columnar transposition ciphers.'
}
