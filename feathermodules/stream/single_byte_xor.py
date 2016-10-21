import cryptanalib as ca
import feathermodules

def single_byte_xor_attack(ciphertexts):
   options = dict(feathermodules.current_options)
   results = []
   print '[+] Running single-byte XOR brute force attack...'
   try:
      num_answers = int(options['number_of_answers'])
   except:
      return '[*] Could not interpret number_of_answers option as a number.'
   if num_answers > 256:
      return '[*] Bad option value for number_of_answers.'
   for ciphertext in ciphertexts:
      results.append(ca.break_single_byte_xor(ciphertext, num_answers=num_answers))
   print 'Best candidate decryptions:\n' + '-'*40 + '\n'
   output = []
   for result in results:
      print '\n'.join(['%r (score: %f)' % (candidate_decryption[0],candidate_decryption[1][0]) for candidate_decryption in result])
      print '\n'
      output.append([x[0] for x in result])
   return output


feathermodules.module_list['single_byte_xor'] = {
   'attack_function':single_byte_xor_attack,
   'type':'stream',
   'keywords':['individually_low_entropy'],
   'description':'A brute force attack against single-byte XOR encrypted ciphertext.',
   'options':{
      'number_of_answers': '3'
   }
}
