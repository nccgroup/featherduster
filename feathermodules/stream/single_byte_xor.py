import cryptanalib as ca
import feathermodules

def single_byte_xor_attack(ciphertexts):
   arguments = get_arguments(ciphertexts)
   results = []
   print '[+] Running single-byte XOR brute force attack...'
   for ciphertext in arguments['ciphertexts']:
      results.append(ca.break_single_byte_xor(ciphertext))
   return results

def get_arguments(ciphertexts):
   arguments = {}
   arguments['ciphertexts'] = ciphertexts
   return arguments


feathermodules.module_list['single_byte_xor'] = {
   'attack_function':single_byte_xor_attack,
   'type':'stream',
   'keywords':['individually_low_entropy'],
   'description':'A brute force attack against single-byte XOR encrypted ciphertext.',
   'options':{}
}
