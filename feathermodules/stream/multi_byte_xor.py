import cryptanalib as ca
import feathermodules

def multi_byte_xor_attack(ciphertexts):
   arguments = get_arguments(ciphertexts)
   results = []
   print 'Running multi-byte XOR brute force attack...'
   for ciphertext in arguments['ciphertexts']:
      results.append(ca.break_multi_byte_xor(ciphertext, verbose=True)[0])
   return results

def get_arguments(ciphertexts):
   arguments = {}
   arguments['ciphertexts'] = ciphertexts
   return arguments


feathermodules.module_list['multi_byte_xor'] = {
   'attack_function':multi_byte_xor_attack,
   'type':'stream',
   'keywords':['individually_low_entropy', 'collectively_low_entropy'],
   'description':'A brute force attack against multi-byte XOR encrypted ciphertext.'
}
