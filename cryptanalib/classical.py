'''
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCrypto, GMPy
'''

# Get helper functions
from helpers import *

import string
import frequency
import operator

# -------------------------
# Classical cryptography functions
# 
# This section contains functions useful for solving CTF and challenge site
# challenges. In general, you won't see cryptosystems vulnerable to these attacks
# being used in the real world. If you do, you should laugh.
#--------------------------

'''
TODO: this sucks, add digraph/trigraph detection? word detection?
consider implementing quipqiup method
FIXME: Currently this function is broken as frequency tables now
include digraphs and translating based on mixed single chars and
digraphs doesn't work as originally written
'''
def break_simple_substitution(ciphertext, freq_table=frequency.frequency_tables['english'], num_answers=5):
   '''Currently broken. Please do not use.'''
   ciphertext_freq = generate_frequency_table(ciphertext, freq_table.keys())
   ''' Experiments in frequency matching...
   closest_match = ('', 1)
   plaintext_charset = []
   ciphertext_charset = []
   for pt_char, pt_frequency in freq_table.items():
      for ct_char, ct_frequency in ciphertext_freq.items():
         current_match = abs(ct_frequency-pt_frequency)
         if current_match < closest_match[1]:
            closest_match = (ct_char, current_match)
      plaintext_charset += pt_char
      ciphertext_charset += closest_match[0]
      closest_match = ('', 1)
   '''
   #old method - sort tables by frequency and map characters directly
   plaintext_charset = [x[0] for x in sorted(freq_table.items(), key=operator.itemgetter(1), reverse=True)]
   ciphertext_charset = [x[0] for x in sorted(ciphertext_freq.items(), key=operator.itemgetter(1), reverse=True)]
   # 
   answers = []
   candidate_charset = plaintext_charset
   for offset in xrange(len(plaintext_charset)-1):
      candidate_charset[offset],candidate_charset[offset+1] = candidate_charset[offset+1],candidate_charset[offset]
      answers.append(do_simple_substitution(ciphertext, candidate_charset, ciphertext_charset))
      candidate_charset[offset],candidate_charset[offset+1] = candidate_charset[offset+1],candidate_charset[offset]
   return sorted(answers, key=detect_plaintext)[:num_answers]



def break_generic_shift(ciphertext, charset, num_answers=1):
   '''Generic shift cipher brute forcer'''
   answers = []
   charset_len = len(charset)
   for offset in xrange(charset_len):
      plaintext = ''
      for char in ciphertext:
         if char in charset:
            plaintext += charset[(charset.find(char)+offset)%charset_len]
         else:
            plaintext += char
      answers.append(plaintext)
   return sorted(answers, key=detect_plaintext)[:num_answers]

def break_alpha_shift(ciphertext, num_answers=1):
   '''Call generic shift cipher breaker with lowercase letters'''
   return break_generic_shift(ciphertext.lower(), string.lowercase, num_answers=num_answers)

def break_ascii_shift(ciphertext):
   '''Call generic shift cipher breaker with full ASCII range'''
   return break_generic_shift(ciphertext, map(chr,range(256)))


def break_rail_fence(ciphertext):
   print 'todo'

def break_columnar_transposition(ciphertext, pt_freq_table=frequency.frequency_tables['english'], num_answers=1, single_chars_only=False):
   '''Uses brute force and plaintext detection to break columnar transposition'''
   results = {}
   ciphertext_len = len(ciphertext)
   for num_cols in range(2,ciphertext_len/2):
      result = ''.join([ciphertext[num::num_cols] for num in xrange(num_cols)])
      results[result] = detect_plaintext(result, pt_freq_table=pt_freq_table, detect_words=True, single_chars_only=single_chars_only)
   return sorted(results.items(),key=operator.itemgetter(1))[:num_answers]

