import cryptanalib as ca
import feathermodules
import pymd5

def hash_extend_attack(ciphertexts):
   """Consume the arguments and redirect to the hash-specific attack function"""
   arguments = get_arguments(ciphertexts)
   if arguments['hash_type'] == 'md5':
      return hash_extend_md5(arguments['ciphertext'], arguments['original_plaintext'])

def generate_hash_padding(original_plaintext, endianness='little')
   
   

def get_arguments(ciphertexts):
   arguments = {}

   for uid, ciphertext in zip(range(1,len(ciphertexts)+1),ciphertexts):
      print '%d) %s' % (uid, ciphertext)
   
   while True:
      if len(ciphertexts) == 1:
         arguments['ciphertext'] = ciphertexts[0]
         break

      selection = raw_input('Please select the hash you\'d like to extend:')
      try:
         selection = int(selection)
      except:
         print 'Selection was not a number. Please try again.'
         continue
   
      if 0 < selection < len(ciphertexts)+1:
         arguments['ciphertext'] = ciphertexts[selection-1]
         break
      else:
         print 'Selection was outside the range of valid options. Please try again.'
         continue
  
   if len(arguments['ciphertext']) == 16:
      while True:
         hash_type = raw_input('The hash appears to be either MD4 or MD5. Which algorithm would you like to use (md5)?')
         if hash_type.lower() in ['md5','']:
            arguments['hash_type'] = 'md5'
            break
         elif hash_type.lower() == 'md4':
            arguments['hash_type'] = 'md4'
            break
         else:
            print 'Sorry, your input was not recognized as a valid option. Please try again.'
            continue

   elif len(arguments['ciphertext']) == 20:
      while True:
         hash_type = raw_input('The hash appears to be either SHA-1 or RIPEMD-160. Which algorithm would you like to use (sha1)?')
         
         if hash_type.lower() in ['sha1','sha-1','sha','']:
            arguments['hash_type'] = 'sha1'
         elif hash_type.lower() in ['ripemd','ripemd-160','ripemd160','ripe']:
            arguments['hash_type'] = 'ripemd160'
         else:
            print 'Sorry, your input was not recognized as a valid option. Please try again.'
            continue

   return arguments


feathermodules.module_list['hash_extend_attack'] = {
   'attack_function':hash_extend_attack,
   'type':'hash',
   'keywords':['md_hashes','sha1_hashes','sha2_hashes'],
   'description':'Given any hash, generate the equivalent hash for the data of your choosing appended to the original input.',
   'options':{}
}
