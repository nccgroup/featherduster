import cryptanalib as ca
import feathermodules

def detect_hash_format(hashes):
   options = feathermodules.current_options
   if options['words'] == '' or ',' not in options['words']:
      options['words'] = raw_input('Please enter words that might be in the plaintext version of the hashes, comma-separated: ').split(',')
   else:
      options['words'] = options['words'].split(',')
   result = ca.detect_hash_format(options['words'],hashes)
   if result == False:
      print '[+] Could not detect hash format.'
      return False
   else:
      print '[!] Plaintext: {}\n[!] Hash algorithm: {}'.format(result)
      return [':'.join(result)]


feathermodules.module_list['detect_hash_format'] = {
   'attack_function':detect_hash_format,
   'type':'auxiliary',
   'keywords':['md_hashes','sha1_hashes','sha2_hashes'],
   'description':'Try hashing all permutations of provided words with different delimiters to determine how data is put together before hashing.',
   'options':{'words':'firstword,secondword'}
}
