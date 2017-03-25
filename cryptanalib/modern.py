'''
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCrypto, GMPy
'''

from Crypto.Hash import *
from Crypto.PublicKey import RSA

from helpers import *

import string
import frequency
import operator
import itertools
import sys
import gmpy
import zlib

#-----------------------------------------
# Real-world attack functions
#
# These functions are meant to be called directly to attack cryptosystems implemented
# with modern crypto, or at least cryptosystems likely to be found in the real world.
#-----------------------------------------

def lcg_next_states(known_states_in_order, num_states=5, a='unknown', c='unknown', m='unknown'):
   '''
   Given the current state of an LCG, return the next states
   in sequence.
   
   Currently, the A, C, and M values must be known.
   
   known_states_in_order - (list of ints) Known states from the
      LCG.
   num_states - (int) The number of future states to generate.
   a - (int) The multiplier for the LCG.
   c - (int) The addend for the LCG.
   m - (int) The modulus for the LCG.
   '''
   #TODO: allow a,c,m recovery for unknown values
   if any([x=='unknown' for x in [a,c,m]]):
      print 'a,c,m recovery not yet implemented.'
      return False
   
   current_state = known_states_in_order[-1]
   next_states = []
   for i in xrange(num_states):
      current_state = (a * current_state + c) % m
      next_states.append(current_state)

   return next_states


def lcg_prev_states(known_states_in_order, num_states=5, a='unknown', c='unknown', m='unknown'):
   '''
   Given the current state of an LCG, return the previous states
   in sequence.
   
   Currently, the A, C, and M values must be known.
   
   known_states_in_order - (list of ints) Known states from the
      LCG.
   num_states - (int) The number of past states to generate.
   a - (int) The multiplier for the LCG.
   c - (int) The addend for the LCG.
   m - (int) The modulus for the LCG.
   '''
   #TODO: allow a,c,m recovery for unknown values
   if any([x=='unknown' for x in [a,c,m]]):
      print 'a,c,m recovery not yet implemented.'
      return False

   current_state = known_states_in_order[0]
   prev_states = []
   for i in xrange(num_states):
      current_state = (a * gmpy.invert(current_state - c, m)) % m
      prev_states.insert(0,current_state)

   return prev_states


def libc_rand_next_states(known_states_in_order, num_states):
   '''
   A wrapper around lcg_next_states with hardcoded
   a, c, and m parameters.
   '''
   return lcg_next_states(known_states_in_order, num_states, a=1103515245, c=12345, m=2**31)

def libc_rand_prev_states(known_states_in_order, num_states):
   '''
   A wrapper around lcg_prev_states with hardcoded
   a, c, and m parameters corresponding to libc rand(),
   used in C and Perl 
   '''
   return lcg_prev_states(known_states_in_order, num_states, a=1103515245, c=12345, m=2**31)



def rsa_crt_fault_attack(faulty_signature, message, modulus, e=0x10001, verbose=False):
   '''
   Given a faulty signature, a message (with padding, if any, applied),
   the modulus, and public exponent, one can derive the private key used
   to sign the message.
   
   faulty_signature - (long) A signature generated incorrectly
   message - (long) The signed message, as a number, with padding applied
   modulus - (long) The public modulus
   e - (long) The public exponent [defaults to the common 0x10001]

   Returns the private exponent if found, or False.
   '''
   p = gcd( pow(faulty_signature, e, modulus) - message, modulus )

   if p == 1:
      if verbose:
         print '[*] Couldn\'t factor the private key.'
      return False
   else:
      q = modulus / p
      d = derive_d_from_pqe(p,q,e)
      print '[!] Factored private key.'
      return d


def recover_rsa_modulus_from_signatures(m1, s1, m2, s2, e=0x10001):
   """
   Calculates the modulus used to produce RSA signatures from
   two known message/signature pairs and the public exponent.

   Since the most common public exponent is 65537, we default
   to that.
   
   Parameters:
   m1 - (string) The first message
   s1 - (string) The signature of the first message
      as an unencoded string
   m2 - (string) The second message
   s2 - (string) The signature of the second message
   e - (int) The exponent to use

   Returns the modulus as an integer, or False upon failure.
   """
   m1 = string_to_long(m1)
   s1 = string_to_long(s1)
   m2 = string_to_long(m2)
   s2 = string_to_long(s2)
   gcd_result = gmpy.gcd( s1 ** e - m1, s2 ** e - m2 )

   if gcd_result < s1 or gcd_result < s2:
      # The modulus can never be smaller than our signature.
      # If this happens, we have been fed bad data.
      return False

   else:
      return int(gcd_result)



def small_message_rsa_attack(ciphertext, modulus, exponent, num_answers=10, minutes=5, frequency_table=frequency.frequency_tables['english'], verbose=False, cribs=frequency.common_words['english']):
   """
   With unpadded RSA, a sufficiently small exponent/message in comparison
   to the size of the modulus may result in a situation where the message,
   after exponentiation, does not exceed the bounds of the modulus, reducing
   decryption to:
   
   plaintext = ciphertext ** (1/exponent)

   Alternatively, there may be some small value for x such that:

   plaintext = (ciphertext + x*modulus) ** (1/exponent)
   
   Since unpadded RSA plaintexts lack structure, this module uses frequency
   analysis to identify the most likely successful decryptions.

   This attack requires a ciphertext, modulus, and public exponent as inputs.

   Optionally, you can also provide:

   num_answers (int) - The number of potential answers to return
   minutes (int) - A number of minutes to run the attack until giving up
   frequency_table (such as is generated by generate_frequency_table) -
      statistical information about the expected format of the plaintext
   verbose (bool) - Whether or not to print status information. Slow.
   cribs (list of strings) - A set of strings that are likely to occur in
      the plaintext
   """
   from time import time
   current_time = int(time())
   end_time = current_time + (minutes * 60)

   answers = []
   
   count = multiplier = 1

   ciphertext = gmpy.mpz(ciphertext)

   if verbose:
      print "Starting small message RSA attack..." 

   while True:
      candidate_plaintext = (ciphertext + multiplier*modulus).root(exponent)[0]
      candidate_plaintext = long_to_string(long(candidate_plaintext))
      score = detect_plaintext(candidate_plaintext, pt_freq_table=frequency_table,
         common_words=cribs)
      answers.append((candidate_plaintext, score))
      answers.sort(key=lambda x: x[1])
      if multiplier > num_answers:
         answers.pop()
      if count % 10 == 0:
         if time() > end_time:
            if verbose: print ''
            return answers
         else:
            if verbose:
               sys.stdout.write("\rCurrent iteration: %d" % count)
               sys.stdout.flush()

      count += 1
      multiplier += 1   
   
   
def wiener(N, e, minutes=10, verbose=False):
   """
   Wiener's attack against weak RSA keys:
   https://en.wikipedia.org/wiki/Wiener%27s_attack

   Developed by Maxime Puys.

   N - interger, modulus of the RSA key to factor using Wiener's attack.
   e - interger, public exponent of the RSA key.
   minutes - number of minutes to run the algorithm before giving up
   verbose - (bool) Periodically show how many iterations have been
   """
   from time import time
   current_time = int(time())
   end_time = current_time + int(minutes * 60)

   def contfrac(x, y):
      """
      Returns the continued fraction of x/y as a list.
      """

      a = x//y
      b = a*y
      ret = [a]
      while b != x:
         x, y = y, x-b
         a = x//y
         b = a*y
         ret += [a]
     
      return ret

   def continuants(frac):
      """
      Returns the continuants of the continued fraction frac.
      """

      prec = (frac[0], 1)
      cur  = (frac[1]*frac[0]+1, frac[1])
      
      ret = [prec, cur]
      for x in frac[2:]:
          cur,prec = (x*cur[0] + prec[0], x*cur[1] + prec[1]), cur
          ret += [cur]

      return ret


   def sqrt(n):
      return gmpy.sqrt(n)

   def polRoot(a, b, c):
      """
      Return an integer root of polynom ax^2 + bx + c.
      """

      delta = abs(b*b - 4*a*c)
      return (-b - sqrt(delta))/(2*a)

   if verbose:
       print "Computing continued fraction."

   frac = contfrac(e, N)

   if verbose:
       print "Computing continuants from fraction."

   conv = continuants(frac)
   current_continuant = 1
   total_continuants = len(conv)

   for k, d in conv:
      if time() > end_time:
         if verbose:
             print "Time expired, returning 1."
             return 1

      if k>0:
         phi = (e*d - 1)//k
         if verbose:
              sys.stdout.write("\rTesting continuant %d of %d" % (current_continuant, total_continuants))
              current_continuant += 1

         root = polRoot(1, N-phi+1, N)

         if root != 0:
             if N%root == 0:
                if verbose:
                    print "\nModulus factored!"
                return -root

   return 1


def fermat_factor(N, minutes=10, verbose=False):
   """
   Code based on Sage code from FactHacks, a joint work by
   Daniel J. Bernstein, Nadia Heninger, and Tanja Lange.

   http://facthacks.cr.yp.to/
   
   N - integer to attempt to factor using Fermat's Last Theorem
   minutes - number of minutes to run the algorithm before giving up
   verbose - (bool) Periodically show how many iterations have been
      attempted
   """
   from time import time
   current_time = int(time())
   end_time = current_time + int(minutes * 60)

   def sqrt(n):
      return gmpy.fsqrt(n)
  
   def is_square(n):
      sqrt_n = sqrt(n)
      return sqrt_n.floor() == sqrt_n

   if verbose:
      print "Starting factorization..."
   
   gmpy.set_minprec(4096)

   N = gmpy.mpf(N)
   if N <= 0:        return [1,N]
   if N % 2 == 0:    return [2,N/2]

   a = gmpy.mpf(gmpy.ceil(sqrt(N)))
   count = 0

   while not is_square(gmpy.mpz(a ** 2 - N)):
      a += 1
      count += 1
      if verbose:
         if (count % 1000000 == 0):
            sys.stdout.write("\rCurrent iterations: %d" % count)
            sys.stdout.flush()
      if time() > end_time:
         if verbose: print "\nTime expired, returning [1,N]"
         return [1,N]

   b = sqrt(gmpy.mpz(a ** 2 - N))
   print "\nModulus factored!"
   return [long(a - b), long(a + b)]



def bb98_padding_oracle(ciphertext, padding_oracle, exponent, modulus, verbose=False, debug=False):
   """
   Bleichenbacher's RSA-PKCS1-v1_5 padding oracle from CRYPTO '98
   
   Given an RSA-PKCS1-v1.5 padding oracle and a ciphertext,
   decrypt the ciphertext.

   ciphertext - The ciphertext to decrypt
   padding_oracle - A function that communicates with the padding oracle.
      The function should take a single parameter as the ciphertext, and
      should return either True for good padding or False for bad padding.
   exponent - The public exponent of the keypair
   modulus - The modulus of the keypair
   verbose - (bool) Whether to show verbose output
   debug - (bool) Show very verbose output
   """
   # Preamble:
   exponent = gmpy.mpz(exponent)
   bit_length = gmpy.mpz(modulus).bit_length()
   bit_length += (bit_length % 8)
   k = bit_length / 8
   B = 2 ** ( 8 * (k-2) )
   # constants to avoid recomputation
   B2 = 2 * B
   B3 = 3 * B

   def get_r_values(s, M):
      R = []
      for a,b in M:
         low_val = gmpy.ceil( (a * s - B3 + 1)/modulus )
         high_val = gmpy.floor( ((b * s - B2)/modulus))
         R.extend([x for x in range(int(low_val),int(high_val+1))])
      if verbose and len(R) > 1:
         print "Found %d possible r values, trying to narrow to one..." % len(R)
      return R


   def step2(search_number, i, M):
      if i == 1 or len(M) > 1:
         # Step 2a/2b
         while True:
            if debug:
               sys.stdout.write("\rCurrent search number: %d" % search_number)
               sys.stdout.flush()
            search_number += 1
            test_ciphertext = c0 * search_number ** exponent
            test_ciphertext %= modulus
            if padding_oracle(test_ciphertext.binary()[::-1]):
               if verbose:
                  print "Found s0! Starting to narrow search interval..."
               return(search_number)
      else:
         # Step 2c 
         a = list(M)[0][0]
         b = list(M)[0][1]
         r = gmpy.ceil( 2*(b * search_number - B2)/modulus )
         while True:
            s_range_bottom = gmpy.ceil(( B2 + r * modulus ) / b)
            s_range_top = gmpy.floor(( B3-1 + r * modulus ) / a)
            s = gmpy.mpz(s_range_bottom)
            while s <= s_range_top:
               test_ciphertext = c0 * s ** exponent
               test_ciphertext %= modulus
               if padding_oracle(test_ciphertext.binary()[::-1]):
                  return(s)
               s += 1
            r += 1
  

   def step3(s, M, R):
      new_M = set([])
      for a,b in M:
         for r in R:
            new_a = max(a, gmpy.ceil( (B2 + r * modulus)/s ) )
            new_b = min(b, gmpy.floor( (B3 - 1 + r * modulus)/s ) )
            if new_a <= new_b:
               new_M |= set([(new_a, new_b)])
      return new_M
   


   # Step 1: Blinding
   # Pseudocode:
   randint = 1 # "random" integer lol
   ct_is_pkcs_conforming = padding_oracle(ciphertext)
   if ct_is_pkcs_conforming:
      c0 = gmpy.mpz(string_to_long(ciphertext))
      M = set([(B2, B3 - 1)])
      if verbose:
         print "Original ciphertext is PKCS conforming, skipping blinding step and searching for s0..."
   while ct_is_pkcs_conforming == False:
      randint += 1
      c0 = gmpy.mpz(string_to_long(ciphertext)) * randint ** exponent
      c0 %= modulus
      if padding_oracle(c0.binary()[::-1]):
         if verbose:
            print "Blinding complete. Searching for s0..."
         M = set([(B2, B3 - 1)])
         ct_is_pkcs_conforming = True

   s = modulus/(B3)
   i = 1

   while True:
      # Step 2: Searching for PKCS conforming messages
      s = step2(s, i, M)
      # Step 3: Narrowing the set of solutions
      R = get_r_values(s, M)
      M = step3(s, M, R)
      # Step 4: Computing the solution
      list_M = list(M)
      interval_bit_length = (gmpy.mpz(list_M[0][1]) - gmpy.mpz(list_M[0][0])).bit_length()
      if verbose and (len(M) == 1):
         sys.stdout.write("\rCurrent interval bit length: %d | Iterations finished: %d  " % (interval_bit_length, i))
         sys.stdout.flush()
      if debug:
         print 'Current possible message space: %r' % list_M
      if len(M) == 1 and interval_bit_length < 8:
         for message in range(list_M[0][0],list_M[0][1]+1):
            if pow(message, exponent, modulus) == c0:
               return long_to_string(message) # FIXME Doesn't work for non-PKCS-conforming ciphertext
         # Something went wrong...
         print 'Debug: approximate message is {}'.format(repr(list_M[0][0].binary()))
         return False
      i += 1



def xor_known_plaintext(matched_plaintext,matched_ciphertext,unmatched_ciphertext):
   """
   Given matching plaintext/ciphertext values, derive the key
   and decrypt another ciphertext encrypted under the same key.

   matched_plaintext - The plaintext half of a plaintext/ciphertext pair
   matched_ciphertext - The ciphertext half of a plaintext/ciphertext pair
   unmatched_ciphertext - A ciphertext whose plaintext is unknown
   """
   return sxor(sxor(matched_plaintext,matched_ciphertext),unmatched_ciphertext)



def cbc_edit(old_plaintext,new_plaintext,old_ciphertext):
   '''
   Calculate the new ciphertext needed to make particular edits to plaintext
   through ciphertext modification.

   old_plaintext - The old block of plaintext to be modified
   new_plaintext - The new block of plaintext to be modified
   old_ciphertext - The block of ciphertext to modify in order to make the
      changes. For CBC mode ciphertext, this is the previous block or IV.
      For stream ciphertext, this is the block of ciphertext corresponding
      to the old_plaintext.
   '''
   if not (len(old_plaintext) == len(new_plaintext) == len(old_ciphertext)):
      raise InputLengthException

   edits = sxor(old_plaintext,new_plaintext)
   return sxor(old_ciphertext,edits)




def analyze_ciphertext(data, verbose=False):
   '''
   Takes in a list of samples and analyzes them to determine what type
   of samples they may be.
   
   Checks for:
   Randomness of the data (to identify output of a CSPRNG/RNG/strong cipher)
   zlib compression
   ASCII hex encoding
   Base64 encoding
   Block cipher vs Stream cipher
   ECB mode
   CBC with fixed IV
   Hashes based on a Merkle-Damgard construction
   OpenSSL formatted encrypted data
   Stream cipher key reuse
   
   data - A list of samples to analyze
   verbose - (bool) Display messages regarding analysis results
   '''
   data = filter(lambda x: x is not None and x is not '', data)
   results = {}
   result_properties = ['ecb', 'cbc_fixed_iv', 'blocksize', 'md_hashes',
   'sha1_hashes', 'sha2_hashes', 'individually_random', 'collectively_random', 'is_openssl_formatted', 'decoded_ciphertexts', 'key_reuse', 'rsa_key', 'rsa_private_key', 'rsa_small_n']
   result_properties.extend(['is_transposition_only', 'is_polybius', 'is_all_alpha'])
   for result_item in result_properties:
      results[result_item]=False
   results['keywords'] = []
   data_properties = {}
   rsa_moduli = []
   num_messages = len(data)
   for datum, index in zip(data, xrange(num_messages)):
      # analyze each ciphertext to determine various individual properties
      data_properties[index]={}
      data_properties[index]['is_openssl_formatted'] = (datum[:8] == "Salted__")
      data_properties[index]['base64_encoded'] = is_base64_encoded(datum)
      data_properties[index]['hex_encoded'] = is_hex_encoded(datum)
      data_properties[index]['zlib_compressed'] = is_zlib_compressed(datum)
      data_properties[index]['blocksize'] = detect_block_cipher(datum)

      # Check if sample is RSA key, if so, check properties
      (data_properties[index]['rsa_key'],
       data_properties[index]['rsa_private_key'],
       data_properties[index]['rsa_n_length']) = check_rsa_key(datum)

      # check for silly/classical crypto here
      data_properties[index]['is_transposition_only'] = (detect_plaintext(datum.lower(),frequency.frequency_tables['single_english_icase_letters']) < 1)
      data_properties[index]['is_polybius'] = detect_polybius(datum)
      data_properties[index]['is_all_alpha'] = all([char in ' '+string.lowercase for char in datum.lower()])
   if all([data_properties[datum]['is_openssl_formatted'] for datum in data_properties]):
      if verbose:
         print '[+] Messages appear to be in OpenSSL format. Stripping OpenSSL header and analyzing again.'
      return analyze_ciphertext(map(lambda x: x[16:],data), verbose=verbose)
   if all([data_properties[datum]['hex_encoded'] for datum in data_properties]):
      if verbose:
         print '[+] Messages appear to be ASCII hex encoded, hex decoding and analyzing again.'
      return analyze_ciphertext(map(lambda x: x.decode('hex'),data), verbose=verbose)
   if all([data_properties[datum]['zlib_compressed'] for datum in data_properties]):
      if verbose:
         print '[+] Messages appear to be zlib compressed, decompressing and analyzing again.'
      return analyze_ciphertext(map(lambda x: zlib.decompress(x),data), verbose=verbose)
   if all([data_properties[datum]['base64_encoded'] and not data_properties[datum]['is_all_alpha'] for datum in data_properties]):
      if verbose:
         print '[+] Messages appear to be Base64 encoded, Base64 decoding and analyzing again.'
      return analyze_ciphertext(map(lambda x: x.decode('base64'),data), verbose=verbose)
   min_blocksize = min([data_properties[datum]['blocksize'] for datum in data_properties])
   
   # perhaps we're dealing with hashes?
   if len(set([len(datum) for datum in data])) == 1:
      sample_length = list(set([len(datum) for datum in data]))[0]
      if sample_length == 16:
         results['md_hashes'] = True
         results['keywords'].append('md_hashes')
         if verbose:
            print '[+] Messages are all of length 16. This suggests MD5, MD4, or MD2 hashes.'
            print '[!] Consider attempting hash-length extension attacks.'
            print '[!] Consider attempting brute-force attacks.'
      elif sample_length == 20:
         results['sha1_hashes'] = True
         results['keywords'].append('sha1_hashes')
         if verbose:
            print '[+] Messages are all of length 20. This suggests RIPEMD-160 or SHA1 hashes.'
            print '[!] Consider attempting hash-length extension attacks.'
            print '[!] Consider attempting brute-force attacks.'
      elif sample_length in [28,32,48,64]:
         results['sha2_hashes'] = True
         results['keywords'].append('sha2_hashes')
         if verbose:
            print '[+] Messages all have equal length matching one possible output length of SHA-2 hashes.'
            print '[!] Consider attempting hash-length extension attacks.'
            print '[!] Consider attempting brute-force attacks.'
   
   # Are we dealing with RSA keys?
   if all([data_properties[datum]['rsa_key'] for datum in data_properties]):
      if verbose:
         print '[+] At least one RSA key was discovered among the samples.'
      results['keywords'].append('rsa_key')
      # Any private keys?
      if any([data_properties[datum]['rsa_private_key'] for datum in data_properties]):
         if verbose:
            print '[!] At least one of the RSA keys discovered contains a private key component.'
      # Any critically small primes?
      if any([0 < data_properties[datum]['rsa_n_length'] <= 512 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print '[!] At least one of the RSA keys discovered has a bit length <= 512. This key can reasonably be factored with a single off-the-shelf computer.'
      # Any proven dangerously small primes?
      elif any([0 < data_properties[datum]['rsa_n_length'] < 768 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print '[!] At least one of the RSA keys discovered has a bit length <= 768. This key can be factored with a large number of computers such as a botnet, or large cluster.'
      # Any theoretical dangerously small primes?
      elif any([0 < data_properties[datum]['rsa_n_length'] < 1024 for datum in data_properties]):
         results['keywords'].append('rsa_small_n')
         if verbose:
            print '[!] At least one of the RSA keys discovered has a bit length <= 1024. This key can be factored with a large number of computers such as a botnet, or large cluster.'
      if len(set(rsa_moduli)) < len(rsa_moduli):
         results['keywords'].append('rsa_n_reuse')
         if verbose:
            print '[!] Two or more of the keys have the same modulus. Anyone who holds the private component for one of these keys can derive the private component for any of the others.'
            
   elif min_blocksize:
      results['keywords'].append('block')
      results['blocksize'] = min_blocksize
      if verbose:
         print '[+] Messages may be encrypted with a block cipher with block size ' + str(min_blocksize) + '.'
         print '[!] Consider attempting padding oracle attacks.'
         if min_blocksize == 32:
            print '[+] A block size of 32 is rare. The real block size is more likely 16 or 8.'
      for datum in data:
         if detect_ecb(datum)[0]:
            results['ecb'] = True
            results['keywords'].append('ecb')
      if (results['ecb'] == True) and verbose:
         print '[!] ECB mode detected. ECB mode has known vulnerabilities.'
         print '[!] Consider attempting block shuffling attacks.'
         print '[!] Consider attempting bytewise ECB decryption.'
      if not results['ecb']:
         if detect_ecb(''.join(data))[0]:
            results['cbc_fixed_iv'] = True
            results['keywords'].append('cbc_fixed_iv')
            if verbose:
               print '[!] Duplicate blocks detected between messages. This indicates either ECB mode or CBC mode with a fixed IV.'
               print '[!] Consider attempting bytewise CBC-fixed-IV decryption.'

            
   # we don't appear to be working with a block cipher, so maybe stream cipher or homebrew
   else:
      if verbose:
         print '[+] Messages may be encrypted with a stream cipher or simple XOR.'
      if len(data) > 1:
         results['key_reuse'] = key_reused = check_key_reuse(data)
      else:
         results['key_reuse'] = key_reused = None
      if key_reused:
         results['keywords'].append('key_reuse')
      results['individually_random'] = individually_random = all([is_random(datum) for datum in data])
      if not individually_random:
         results['keywords'].append('individually_low_entropy')
      results['collectively_random'] = collectively_random = is_random(''.join(data))
      if not collectively_random:
         results['keywords'].append('collectively_low_entropy')
      if verbose:
         if individually_random:
            if collectively_random:
               if key_reused:
                  print '[!] Messages have passed randomness tests, but show signs of key reuse.'
                  print '[!] Consider using the break_many_time_pad attack, or attempting crib dragging.'

               else:
                  print '[+] Messages have passed statistical randomness tests individually and collectively.'
                  print '[+] This suggests strong crypto.'

            else:
               print '[!] Messages have passed statistical randomness tests individually, but NOT collectively.'
               print '[!] This suggests key reuse.'
               print '[!] Consider using the break_many_time_pad attack, or attempting crib dragging.'

         else:
            print '[!] Individual messages have failed statistical tests for randomness.'
            print '[!] This suggests weak crypto is in use.'
            print '[!] Consider running single-byte or multi-byte XOR solvers.'

   # checks for silly classical crypto
   if all([data_properties[datum]['is_transposition_only'] for datum in data_properties]) and not 'rsa_key' in results['keywords']:
      results['is_transposition_only'] = True
      results['keywords'].append('transposition')
      if verbose:
         print '[!] Ciphertexts match the frequency distribution of a transposition-only ciphertext.'
         print '[!] Consider using transposition solvers (rail fence, columnar transposition, etc)'
   if all([data_properties[datum]['is_polybius'] for datum in data_properties]):
      results['is_polybius'] = True
      results['keywords'].append('polybius')
      if verbose:
         print '[!] Ciphertexts appear to be a grid cipher (like polybius).'
         print '[!] Consider running simple substitution solvers.'
   if all([data_properties[datum]['is_all_alpha'] for datum in data_properties]):
      results['is_all_alpha'] = True
      results['keywords'].append('alpha')
      if verbose:
         print '[!] Ciphertexts are all alphabet characters.'
         print '[!] Consider running an alphabetical shift solver.'
   results['decoded_ciphertexts'] = data
   return results


def ecb_cpa_decrypt(encryption_oracle, block_size, verbose=False, hollywood=True, charset=frequency.optimized_charset['english']):
   '''
   Bytewise ECB decryption.
   
   Parameters:
   (function) encryption_oracle - A function that will encrypt arbitrary data in ECB mode with
      a fixed secret suffix to be decrypted.
   (int) blocksize - The block size of the cipher in use (usually 8 or 16)
   (bool) verbose - Provide verbose output
   (bool) hollywood - Silly hollywood-style visualization
   (string) charset - A string of characters that could possibly be in the decrypted data, where the first character is the most common and the last is the least common. This should include at the very least all the possible padding characters. For instance, with PKCS#7 style padding, \\x01 through \\x10 should be included in the character set.
   '''
   #------------------------------
   # Helper functions for ECB CPA bytewise decryption
   #
   def find_egg(ciphertext, block_size):
      ciphertext_blocks = split_into_blocks(ciphertext,block_size)
      num_blocks = len(ciphertext_blocks)
      if num_blocks < 4:
         return None
      for offset in xrange(num_blocks-4):
         if (ciphertext_blocks[offset] == ciphertext_blocks[offset+1]) and (ciphertext_blocks[offset+2] == ciphertext_blocks[offset+3]):
            return ((offset * block_size) + (4*block_size))
      return None
   
   def try_forever_egghunt_encryption_oracle(encryption_oracle, block_size, plaintext):
      while True:
         ciphertext = encryption_oracle(plaintext)
         egg_offset = find_egg(ciphertext, block_size)
         if egg_offset != None:
            return ciphertext[egg_offset:]
   #
   #-------------------------------
   
   #-------------------------------
   # Variable setup
   #
   bytes_to_boundary = 0
   # helps us find where our plaintext lies in the ciphertext
   egg = 'A'*(block_size*2)+'B'*(block_size*2)
   # encrypt data of different lengths until egg is found
   bytes_to_boundary = None
   for tries in xrange(20):
      for length in xrange(block_size):
         if find_egg(encryption_oracle( ('A'*length) + egg ), block_size) != None:
            bytes_to_boundary = length
            break
      if bytes_to_boundary != None:
         break
   if bytes_to_boundary == None:
      # For whatever reason, we couldn't get a length after 20 tries
      return False
   # get to the byte boundary so we're aligned to boundaries
   padding = 'A'*bytes_to_boundary
   prev_plaintext_block = 'A'*block_size
   ciphertext_to_decrypt = try_forever_egghunt_encryption_oracle(encryption_oracle,block_size,padding+egg)
   plaintext = ''
   decryption_complete = False
   
   if verbose:
      num_blocks = len(ciphertext_to_decrypt)/block_size
      num_current_block = 0
   #
   #-------------------
   
   # iterate through each block of ciphertext to decrypt
   for offset in xrange(0,len(ciphertext_to_decrypt),block_size):
      if verbose:
         num_current_block += 1
         print "[+] Decrypting block %d of %d" % (num_current_block,num_blocks)
      decrypted_bytes = ''
      # iterate through each byte of each ciphertext block
      for current_byte in xrange(1,block_size+1):
         working_block = prev_plaintext_block[current_byte:]
         # Use the oracle to determine what our working block should look like
         # when we have the correct byte
         correct_byte_block = try_forever_egghunt_encryption_oracle(encryption_oracle,block_size,padding+egg+working_block)[offset:offset+block_size]
         working_block += decrypted_bytes
         # Try each byte until we match the block indicating the correct byte
         for char in charset:
            if verbose and hollywood: 
               # Silly hollywood style visualization of decryption process
               sys.stdout.write("\r" + output_mask(decrypted_bytes,string.printable[:-5]) + output_mask(char*(block_size-current_byte),string.printable[:-5]))
               sys.stdout.flush()
            if try_forever_egghunt_encryption_oracle(encryption_oracle,block_size,padding+egg+working_block+char)[:block_size] == correct_byte_block:
               decrypted_bytes += char
               break
            if char == charset[-1]:
               # We seem to have reached the padding now
               decryption_complete = True
      # set our working block to be the block we've just decrypted so we can
      # correctly compare our "correct_byte_block" to our working block
      prev_plaintext_block = decrypted_bytes
      plaintext += decrypted_bytes
      if verbose:
         print "\n[+] Decrypted block: %s" % decrypted_bytes
   return plaintext

# TODO: recover earlier states from mersenne twister output
def mersenne_untwister(mersenne_state):
   #----------------------
   # Helper functions
   #
   def generate_from_state(mersenne_state):
      print 'todo'
   def recover_state(output_list):
      print 'todo'
   def untemper_integer(sample):
      sample = sample ^ sample << 18
      
   #
   #----------------------
   
   
   
'''
TODO: Extend the attack to other forms of padding that
can be used with Vaudenay's technique
'''
def padding_oracle_decrypt(padding_oracle, ciphertext, block_size, padding_type='pkcs7', iv=None, prefix='',verbose=False, hollywood=True, charset=frequency.optimized_charset['english']):
   '''
   Given a padding oracle function that accepts raw ciphertext and returns
   True for good padding or False for bad padding, and a ciphertext to decrypt:
   Perform Vaudenay's PO -> DO attack
   
   Parameters:
   (function) padding_oracle - A function that takes a ciphertext as its only parameter
      and returns true for good padding or false for bad padding
   (string) ciphertext - The ciphertext to be decrypted
   (int) block_size - The block size of the cipher in use
   (string) padding_type - Type of padding in use. Currently only pkcs7 is supported.
   (string) iv - IV for decryption of first block. Must be one block in length.
   (string) prefix - Ciphertext to place before any ciphertext being sent to the oracle.
   (bool) verbose - Provide direct output and progress indicator
   (bool) hollywood - Do hollywood style progress indication. Requires verbose.
   (string) charset - A string of characters that could possibly be in the decrypted data, where the first character is the most common and the last is the least common. This should include at the very least all the possible padding characters. For instance, with PKCS#7 style padding, \\x01 through \\x10 should be included in the character set.
   '''
   plaintext = intermediate_block = ''
   ciphertext_blocks = split_into_blocks(ciphertext,block_size)
   #--------------
   # Check our parameters to make sure everything has been put in correctly
   #
   if len(prefix) % block_size != 0:
      print '[!] Error: Bad prefix for padding_oracle_decrypt()'
      return False
   if len(ciphertext) % block_size != 0:
      print '[!] Error: Bad ciphertext length for padding_oracle_decrypt()'
      return False
   if iv != None:
      if len(iv) != block_size:
         print '[!] Error: Bad IV length for padding_oracle_decrypt()'
         return False
      # we set the previous block as the IV so that the first block decrypts correctly
      prev_block = iv
   else:
      # If we haven't received an IV, try a block of nulls as this is commonly
      # used as an IV in practice.
      if verbose:
         print '[*] No IV was provided, using a block of null bytes instead. Unless a block of null bytes is being used as the IV, expect the first block to be garbled.'
      prev_block = "\x00"*block_size
   #
   #--------------
   
   num_blocks = len(ciphertext_blocks)
   num_current_block = 1
   if verbose:
      print ""
   # iterate through each block of ciphertext
   for block_to_decrypt in ciphertext_blocks:
      if verbose:
         sys.stdout.write("\rDecrypting block %d of %d" % (num_current_block,num_blocks))
         sys.stdout.flush()
         if hollywood:
            print ""
         num_current_block += 1
      # convert the ciphertext to a list to allow for direct substitutions
      temp_ciphertext = list(prefix + ("\x00" * block_size) + block_to_decrypt)
      flip_index = len(temp_ciphertext) - block_size
      intermediate_block = ''
      # iterate through each byte of each block, and simultaneously, pkcs7 padding bytes
      for current_padding_byte in xrange(1,block_size+1):
         original_byte = prev_block[-current_padding_byte]
         if current_padding_byte != 1:
            temp_ciphertext[flip_index-(current_padding_byte-1):flip_index] = sxor(intermediate_block,chr(current_padding_byte) * (current_padding_byte-1))
         for char in charset:
            if verbose and hollywood:
               # Silly hollywood style visualization of decryption process
               sys.stdout.write("\r" + output_mask(char *(block_size-current_padding_byte) + sxor(intermediate_block,prev_block[-(current_padding_byte-1):]),string.letters+string.digits))
               sys.stdout.flush()
            new_byte = chr((ord(char) ^ current_padding_byte) ^ ord(original_byte))
            temp_ciphertext[flip_index-current_padding_byte] = new_byte
            if padding_oracle(''.join(temp_ciphertext)) == True:
               # Either we have a padding of "\x01" or some other valid padding.
               # If we're flipping the last byte, flip the second to last byte just to be sure.
               if current_padding_byte == 1:
                  temp_ciphertext[flip_index-2] = sxor(temp_ciphertext[flip_index-2],"\x01")
                  if padding_oracle(''.join(temp_ciphertext)) == True:
                     # Current last decrypted byte is 0x01
                     intermediate_byte = chr(0x01 ^ ord(new_byte))
                     break
               else:
                  intermediate_byte = chr(current_padding_byte ^ ord(new_byte))
                  break
            if char == charset[-1]:
               # Right now if we fail to decrypt a byte we bail out.
               # TODO: Do something better? Is there something better?
               print "\r[!] Could not decrypt a byte. Bailing out."
         intermediate_block = intermediate_byte + intermediate_block
      if verbose:
         print "\r[+] Decrypted block: "+sxor(prev_block,intermediate_block)
      plaintext += sxor(prev_block,intermediate_block)
      prev_block = block_to_decrypt
   
   return plaintext
   

def cbcr(new_plaintext, oracle, block_size, is_padding_oracle=False, verbose=False):
   '''
   Duong & Rizzo's CBC-R technique for turning a CBC mode block
   cipher decryption oracle into an encryption oracle
   
   Parameters:
   (string) new_plaintext - Plaintext to encrypt using the CBCR technique
   (function) oracle - A function that calls out to either a CBC decryption oracle
      or CBC padding oracle.
   (int) block_size - block size of cipher in use
   (bool) is_padding_oracle - Indicates whether the oracle function provided is a
      padding oracle
   (bool) verbose - Provide verbose output
   '''
   new_plaintext = pkcs7_pad(new_plaintext, block_size)
   def __padding_decryption_oracle(ciphertext):
      return padding_oracle_decrypt(oracle, ciphertext, block_size, iv="\x00"*block_size)
   if is_padding_oracle:
      decrypt = __padding_decryption_oracle
   else:
      decrypt = oracle
   padding_block = ''
   null_block = new_ciphertext = utility_block = "\x00"*block_size
   # If we have a decryption oracle, we need to prevent padding errors with a valid padding block.
   if is_padding_oracle == False:
      most_of_junk_block = "\x00"*(block_size-1)
      for char in map(chr,range(256)):
         junk_block = most_of_junk_block + char
         if decrypt(junk_block + null_block) != False:
            padding_block = junk_block + null_block
            break

   plaintext_blocks = split_into_blocks(new_plaintext,block_size)[::-1]
   if verbose:
      print "[+] Got a valid padding block, continuing with CBC-R."
      num_blocks = len(plaintext_blocks) 
      count = 0
   for plaintext_block in plaintext_blocks:
      if verbose:
         count += 1
         sys.stdout.write('\rEncrypting block %d of %d' % (count, num_blocks))
      intermediate_block = decrypt(null_block + utility_block + padding_block)[block_size:block_size*2]
      utility_block = sxor(intermediate_block,plaintext_block)
      new_ciphertext = utility_block + new_ciphertext
   return new_ciphertext


def break_single_byte_xor(ciphertext,num_answers=5,pt_freq_table=frequency.frequency_tables['english'], detect_words=True):
   '''
   Return a list of likely successful single byte XOR decryptions sorted by score
   
   ciphertext - Ciphertext to attack
   num_answers - (int) maximum number of answers to return
   pt_freq_table - A frequency table for the expected plaintext, as generated
      by generate_frequency_table().
   '''
   answers = {}
   ciphertext_len = len(ciphertext)
   # Try xor with every possible byte value and score the resulting plaintext
   for key in xrange(256):
      answer = sxor(ciphertext, chr(key)*ciphertext_len)
      answers[answer] = (detect_plaintext(answer,pt_freq_table=pt_freq_table,detect_words=detect_words),key)
   # Return the best resulting plaintexts and associated score sorted by score
   return sorted(answers.items(),key=operator.itemgetter(1))[:num_answers]

def break_multi_byte_xor(ciphertext, max_keysize=40, num_answers=5, pt_freq_table=frequency.frequency_tables['english'], verbose=False):
   '''
   Return a list of likely successful multi-byte XOR decryptions sorted by score
   
   ciphertext - Ciphertext to attack
   max_keysize - Largest keysize to try
   num_answers - (int) maximum number of answers to return
   pt_freq_table - A frequency table for the expected plaintext, as generated
      by generate_frequency_table()
   verbose - (bool) Show progress in the attack
   '''
   pt_freq_table_single_chars = dict(filter(lambda x: len(x[0])==1, pt_freq_table.items()))
   edit_distances = {}
   ciphertext_len = len(ciphertext)
   for keysize in xrange(2,max_keysize+1):
      ciphertext_chunks = split_into_blocks(ciphertext, keysize)
      if len(ciphertext_chunks) < 3:
         break
      edit_distances[keysize] = hamming_distance(ciphertext_chunks[0],ciphertext_chunks[1])
      edit_distances[keysize] += hamming_distance(ciphertext_chunks[1],ciphertext_chunks[2])
      edit_distances[keysize] += hamming_distance(ciphertext_chunks[0],ciphertext_chunks[2])
      edit_distances[keysize] /= (keysize*3.0)
   best_keysizes = sorted(edit_distances.items(),key=operator.itemgetter(1))[0:num_answers]
   best_keysizes = [keysize[0] for keysize in best_keysizes]
   answers = {}
   if verbose:
      chunks_to_process = sum(best_keysizes)
      current_chunk = 1
   for best_keysize in best_keysizes:
      if verbose:
         print "Trying keysize %d" % best_keysize
      ct_chunks = []
      pt_chunks = []
      chunk_count = 1
      for offset in range(best_keysize):
         ct_chunks.append(ciphertext[offset::best_keysize])
      best_key=''
      for ct_chunk in ct_chunks:
         if verbose:
            sys.stdout.write("\rProcessing chunk %d of %d" % (current_chunk, chunks_to_process))
            sys.stdout.flush()
            current_chunk += 1
         best_key += chr(break_single_byte_xor(ct_chunk,1,pt_freq_table=pt_freq_table_single_chars, detect_words=False)[0][1][1])
      answers[best_key] = sxor(ciphertext,best_key*((len(ciphertext)/best_keysize)+1))
      if verbose:
         print ''
   return sorted(answers.values(),key=lambda x: detect_plaintext(x, pt_freq_table=pt_freq_table))[:num_answers]



def break_many_time_pad(ciphertexts, pt_freq_table=frequency.frequency_tables['single_english'], verbose=False):
   '''
   Takes a list of ciphertexts XOR'ed with the same unknown set of bytes
   and breaks them by applying single byte xor analysis technique to
   corresponding bytes in each ciphertext.
   
   Useful for:
   OTP with fixed key
   Stream ciphers with fixed key/IV
   Multi-byte XOR with fixed key
   Block ciphers in a stream mode (CTR, GCM, etc) with fixed key/IV
   
   Returns an array of the best candidate decryption for each ciphertext represented as strings

   ciphertexts - A list of ciphertexts to attack
   pt_freq_table - A frequency table matching the expected frequency
      distribution of the correct plaintext, as generated by
      generate_frequency_table(). Use only frequency tables with
      frequencies for single characters.
   verbose - (bool) Whether or not to show progress
   '''
   def right_pad_with_none(array, length):
      array_tmp = []
      for item in array:
         item_list = list(item)
         item_list.extend([None] * (length - len(item_list)))
         array_tmp.append(item_list)
      return array_tmp


   # Can't do this with <2 samples
   if len(ciphertexts) < 2:
      if verbose:
         print '[!] This attack requires two or more samples.'
      return False
      
   # Need to truncate the longest ciphertext to the length of the second longest
   longest_ct_len = max([len(x) for x in ciphertexts])
   second_longest_ct_len = max([len(x) for x in filter(lambda x: len(x) <= longest_ct_len,ciphertexts)])
   if longest_ct_len != second_longest_ct_len:
      for i in range(len(ciphertexts)):
         if len(ciphertexts[i]) > longest_ct_len:
            ciphertexts[i] = ciphertexts[i][:second_longest_ct_len]

   # Pad the other ciphertexts out with None
   ciphertexts = right_pad_with_none(ciphertexts, second_longest_ct_len)

   zipped_plaintexts = []
   # Separate ciphertext bytes into groups positionally
   zipped_ciphertexts = zip(*ciphertexts)
   if verbose:
      num_slices = len(zipped_ciphertexts)
      num_current_slice = 0
   for zipped_ciphertext in zipped_ciphertexts:
      if verbose:
         num_current_slice += 1
         sys.stdout.write("\rBrute forcing slice %d of %d" % (num_current_slice, num_slices))
         sys.stdout.flush()
      # Remove padding for single byte XOR solve
      joined_zipped_ciphertext = ''.join([x for x in zipped_ciphertext if x is not None])
      result = break_single_byte_xor(joined_zipped_ciphertext, pt_freq_table=pt_freq_table, detect_words=False, num_answers=1, )[0][0]
      result_tmp = list(result)
      result = []
      # Add it back for rearranging
      for index in xrange(len(zipped_ciphertext)):
         if zipped_ciphertext[index] != None:
            result.append(result_tmp.pop(0))
         else:
            result.append(None)
      zipped_plaintexts.append(result)
   if verbose:
      print ''
   final_result = []
   for plaintext in zip(*zipped_plaintexts):
      final_result.append(''.join([char for char in plaintext if char is not None]))
            
   return final_result



# TODO: write a batch GCD function
def batch_gcd(items):
   '''
   Find the greatest common denominator between two numbers in a set of numbers
   
   Useful for attempting to factorize RSA public keys that share primes
   '''
   print 'todo'
   


def detect_hash_format(words, hashes):
   '''
   Take a list of strings, permute and hash them to determine
   some hash like md5("username:password:userid")
   
   Matches against list of hashes provided in raw or hex form as "hashes" param
   
   Returns tuple as (matching_plaintext, hash_type) or False for no match

   words - A list of words that may be in the plaintext
   hashes - A set of captured hashes to check against
   '''
   num_words = len(words)
   if len(words) > 7:
      print 'This will take a very long time. Are you sure? (y/n)'
      if sys.stdin.read(1).lower() != 'y':
         return False
   
   if all([is_hex_encoded(each_hash) for each_hash in hashes]):
      hashes = map(lambda x: x.decode("hex"), hashes)
   
   for inhash in hashes:
      hash_len = len(inhash)
      for num in xrange(1,num_words+1):
         for delimiter in ['',':',';','|',',','-',' ']:
            for candidate in [delimiter.join(permutation) for permutation in itertools.permutations(words,num)]:
               if hash_len == 16:
                  if MD5.new(candidate).digest() == inhash:
                     return (candidate,'md5')
                  if MD4.new(candidate).digest() == inhash:
                     return (candidate,'md4')
                  if MD2.new(candidate).digest() == inhash:
                     return (candidate,'md2')
               elif hash_len == 20:
                  if RIPEMD.new(candidate).digest() == inhash:
                     return (candidate,'ripemd-160')
                  if SHA.new(candidate).digest() == inhash:
                     return (candidate,'sha-1')
               elif hash_len == 28:
                  if SHA224.new(candidate).digest() == inhash:
                     return (candidate,'sha-224')
               elif hash_len == 32:
                  if SHA256.new(candidate).digest() == inhash:
                     return (candidate,'sha-256')
               elif hash_len == 48:
                  if SHA384.new(candidate).digest() == inhash:
                     return (candidate,'sha-384')
               elif hash_len == 64:
                  if SHA512.new(candidate).digest() == inhash:
                     return (candidate,'sha-512')
   # nothing matches
   return False


def hastad_broadcast_attack(key_message_pairs, exponent):
   """
   Uses Hastad's broadcast attack to decrypt a message encrypted under multiple
   unique public keys with the same exponent, where the exponent is lower than
   the number of distinct key/ciphertext pairs.

   key_message_pairs should be in the form of a list of 2-tuples like so:
   [(ciphertext1, pubkey1), (ciphertext2, pubkey2), (ciphertext3, pubkey3)]

   exponent should simply be an integer.

   (This function is based on work by Christoph Egger
   <christoph@christoph-egger.org>
   https://www.christoph-egger.org/weblog/entry/46)
   """
   x,n = chinese_remainder_theorem(key_message_pairs)
   realnum = gmpy.mpz(x).root(exponent)[0].digits()
   
   return realnum


def dsa_repeated_nonce_attack(r,msg1,s1,msg2,s2,n,verbose=False):
   '''
   Recover k (nonce) and Da (private signing key) from two DSA or ECDSA signed messages
   with identical k values
   
   Takes the following arguments:
   string: r (r value of signatures)
   string: msg1 (first message)
   string: s1 (s value of first signature)
   string: msg2 (second message)
   string: s2 (s value of second signature)
   long: n (curve order for ECDSA or modulus (q parameter) for DSA)
   
   adapted from code by Antonio Bianchi (antoniob@cs.ucsb.edu)
   <http://antonio-bc.blogspot.com/2013/12/mathconsole-ictf-2013-writeup.html>
   '''
   r = string_to_long(r)
   s1 = string_to_long(s1)
   s2 = string_to_long(s2)
   # convert messages to sha1 hash as number
   z1 = string_to_long(SHA.new(msg1).digest())
   z2 = string_to_long(SHA.new(msg2).digest())
   
   sdiff_inv = gmpy.invert(((s1-s2)%n),n)
   k = ( ((z1-z2)%n) * sdiff_inv) % n
   
   r_inv = gmpy.invert(r,n)
   da = (((((s1*k) %n) -z1) %n) * r_inv) % n
   
   if verbose:
      print "Recovered k:" + hex(k)
      print "Recovered Da: " + hex(da)
   
   return (k, da)


def retrieve_iv(decryption_oracle,ciphertext,blocksize):
   '''
   Retrieve the IV used in a given CBC decryption by decrypting
   [\x00*(blocksize*2)][ciphertext] and XORing the first two
   resulting blocks of data.
   Takes a decryption oracle function that consumes raw ciphertext
   and returns raw plaintext, a ciphertext, and the block size of
   the cipher.
   Requires at least a two-block long valid ciphertext.
   
   People have the strange habit of using a static IV that's
   identical to the key. This function is really useful there >:3
   
   Returns the IV.
   '''
   if len(ciphertext) < 2*blocksize:
      return False # ciphertext must be at least two blocks long
   test_payload = ("\x00"*(blocksize*2))+ciphertext
   test_result = decryption_oracle(test_payload)
   return sxor(test_result[:blocksize],test_result[blocksize:blocksize*2])

