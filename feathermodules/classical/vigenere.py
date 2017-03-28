# Vigenere cipher FeatherModule by Cyril Stoller
import cryptanalib as ca
import feathermodules

def break_vigenere(ciphertexts):
   options = dict(feathermodules.current_options)
   results = []
   for i, sample in enumerate(ciphertexts):
         keys = ca.break_vigenere(sample,
                                  int(options['key_length_scan_range']),
                                  num_answers=int(options['num_answers']),
                                  max_best_shifts=int(options['num_best_shifts']),
                                  num_key_lengths=int(options['num_key_lengths']),
                                  num_key_guesses=int(options['num_key_guesses']),
                                  coefficient_char_deviation=float(options['coefficient_char_deviation']),
                                  coefficient_word_count=float(options['coefficient_word_count']))
         if keys == False:
            continue
         for key in keys:
            results.append('Key found for sample %d: "%s". Decrypts to: %s' % (i+1, key, ca.translate_vigenere(sample, key, decrypt=True)))

   print '\n'.join(results)
   return results

feathermodules.module_list['vigenere'] = {
   'attack_function': break_vigenere,
   'type':'classical',
   'keywords':['alpha', 'vigenere', 'classical', 'individually_low_entropy'],
   'description':'A module to break vigenere ciphers using index of coincidence for key length detection and frequency analysis.',
   'options':{
      'key_length_scan_range':'11',
      'num_key_lengths':'3',
      'num_best_shifts':'2',
      'num_key_guesses':'100',
      'coefficient_char_deviation':'0.0',
      'coefficient_word_count':'1.0',
      'num_answers':'1'
   }
}

