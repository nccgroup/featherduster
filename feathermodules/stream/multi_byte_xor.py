import cryptanalib as ca
import feathermodules

def multi_byte_xor_attack(ciphertexts):
   options = prepare_options(dict(feathermodules.current_options))
   results = []
   print '[+] Running multi-byte XOR brute force attack...'
   for ciphertext in ciphertexts:
      print '\nBest candidate decryptions for ' + ciphertext[:20] + '...:\n' + '-'*40 + '\n'
      result_list = ca.break_multi_byte_xor(ciphertext, verbose=True, num_answers=options['number_of_answers'])
      print '\n'.join(result_list)
      results.append(result_list)
      
   return results

def prepare_options(options):
   try:
      options['number_of_answers'] = int(options['number_of_answers'])
   except:
      print '[*] Could not interpret number of answers option as a number.'
      return False
   return options


feathermodules.module_list['multi_byte_xor'] = {
   'attack_function':multi_byte_xor_attack,
   'type':'stream',
   'keywords':['individually_low_entropy', 'collectively_low_entropy'],
   'description':'A brute force attack against multi-byte XOR encrypted ciphertext.',
   'options':{
      'number_of_answers': '3'
   }
}
