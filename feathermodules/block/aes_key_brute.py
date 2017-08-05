# AES trial decryption FeatherModule by Daniel Crowley
# 
# Try various common AES keys and check for proper padding

from Crypto.Cipher import AES
import feathermodules

# Our main function
def aes_key_brute(samples):
   # Check that the samples are the correct size to match AES
   if not all([len(sample) % 16 == 0 for sample in samples]):
      return False
   
   default_keylist = [
      '0'*32,
      'f'*32,
      '31323334353637383930313233343536',
      '30313233343536373839303132333435',
      '70617373776f726470617373776f7264', #'passwordpassword'.encode('hex')
      '5f4dcc3b5aa765d61d8327deb882cf99' # md5('password')
   ]

   def decrypt_and_check(cipher, ciphertext):
      '''Decrypt under constructed cipher and return True or False indicating correct pkcs7 padding'''
      pt = cipher.decrypt(ciphertext)
      last_byte = ord(pt[-1])
      if last_byte > 16:
         return False
      elif pt[-last_byte:] == chr(last_byte)*last_byte:
         return True
      else:
         return False

   # Load the current set of options from FD, using dict() so we get a copy
   # rather than manipulating the original dict
   options = dict(feathermodules.current_options)
   results = []
   if options['keyfile'] != '':
      try:
         keys = open(options['keyfile'],'r').readlines()
      except:
         print '[*] Key file is not a set of hex encoded 16 byte values. Using default key list.'
   else:
      keys = default_keylist
   
   # filter samples into one-block samples and multi-block samples
   one_block_samples = filter(lambda x: len(x)==16, samples)
   multi_block_samples = filter(lambda x: len(x) > 16, samples)

   for key in keys:
      key = key.decode('hex')

      # set all bad_decryption flags to False
      ecb_bad_decrypt = cbc_null_iv_bad_decrypt = cbc_key_as_iv_bad_decrypt = cbc_bad_decrypt = False

      # ECB
      for sample in samples:
         cipher = AES.new(key, AES.MODE_ECB)
         # If any decryption fails to produce valid padding, flag bad ECB decryption and break
         if decrypt_and_check(cipher, sample[-16:]) == False:
            ecb_bad_decrypt = True
            break

      # CBC last block with second to last block as IV
      for sample in multi_block_samples:
         cipher = AES.new(key, AES.MODE_CBC, sample[-32:-16])
         # If any decryption fails to produce valid padding, flag bad CBC decryption and break
         if decrypt_and_check(cipher, sample[-16:]) == False:
            cbc_bad_decrypt = True
            break

      if options['known_iv'] != '':
         # CBC with entered IV
         for sample in one_block_samples:
            cipher = AES.new(key, AES.MODE_CBC, options['known_iv'].decode('hex'))
            # If any decryption fails to produce valid padding, flag bad CBC decryption and break
            if decrypt_and_check(cipher, sample) == False:
               cbc_bad_decrypt = True
               break
      else:
         # CBC with null IV
         for sample in one_block_samples:
            cipher = AES.new(key, AES.MODE_CBC, '\x00'*16)
            # If any decryption fails to produce valid padding, flag bad CBC_null_IV decryption and break
            if decrypt_and_check(cipher, sample) == False:
               cbc_null_iv_bad_decrypt = True
               break
         # CBC with key as IV
         for sample in one_block_samples:
            cipher = AES.new(key, AES.MODE_CBC, key)
            # If any decryption fails to produce valid padding, flag bad CBC_key_as_IV decryption and break
            if decrypt_and_check(cipher, sample) == False:
               cbc_key_as_iv_bad_decrypt = True
               break

      if not ecb_bad_decrypt:
         results += key.encode('hex') + ' may be the correct key in ECB mode.'
      if not cbc_bad_decrypt:
         results += key.encode('hex') + ' may be the correct key in CBC mode.'
      if not cbc_null_iv_bad_decrypt:
         results += key.encode('hex') + ' may be the correct key in CBC mode with an all-NUL IV.'
      if not cbc_key_as_iv_bad_decrypt:
         results += key.encode('hex') + ' may be the correct key and static IV in CBC mode.'
         
            
   print 'Potentially correct AES keys:'
   print '-' * 80
   print '\n'.join(results)
   return results


feathermodules.module_list['aes_key_brute'] = {
   'attack_function': aes_key_brute,
   'type':'brute',
   'keywords':['block'],
   'description':'Try a list of potential AES keys (or user-provided list of hex-encoded keys) against a list of AES ciphertexts.',
   'options': {
      'known_iv': '',
      'keyfile': ''
   }
}
