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
from math import sqrt

# -------------------------
# Classical cryptography functions
# 
# This section contains functions useful for solving CTF and challenge site
# challenges. In general, you won't see cryptosystems vulnerable to these attacks
# being used in the real world. If you do, you should laugh.
#--------------------------
morse_table = {
   'a': '.-',
   'b': '-...',
   'c': '-.-.',
   'd': '-..',
   'e': '.',
   'f': '..-.',
   'g': '--.',
   'h': '....',
   'i': '..',
   'j': '.---',
   'k': '-.-',
   'l': '.-..',
   'm': '--',
   'n': '-.',
   'o': '---',
   'p': '.--.',
   'q': '--.-',
   'r': '.-.',
   's': '...',
   't': '-',
   'u': '..-',
   'v': '...-',
   'w': '.--',
   'x': '-..-',
   'y': '-.--',
   'z': '--..',
   '1': '.----',
   '2': '..---',
   '3': '...--',
   '4': '....-',
   '5': '.....',
   '6': '-....',
   '7': '--...',
   '8': '---..',
   '9': '----.',
   '0': '-----'
}

def morse_decode(text, dot='.', dash='-', space=' '):
   '''
   Decodes a Morse encoded message. Optionally, you can provide an alternate
   single character for dot, dash, and space.

   Parameters:
   text - (string) A message to decode
   dot - (char) An alternate dot char
   dash - (char) An alternate dash char
   space - (char) A char to split the text on
   '''
   inverse_morse_table = map(lambda (x,y): (y,x), morse_table.items())
   dot_dash_trans = string.maketrans('.-', dot+dash)
   inverse_morse_table = [(string.translate(x,dot_dash_trans), y) for (x,y) in inverse_morse_table]
   inverse_morse_table = dict(inverse_morse_table)
   return ''.join([inverse_morse_table[char] for char in text.split(space) if char in inverse_morse_table.keys()])


def morse_encode(text, dot='.', dash='-', space=' '):
   '''
   Encodes text into Morse code.
   '''
   dot_dash_trans = string.maketrans('.-', dot+dash)
   translated_morse_table = map(lambda (x,y): (x, string.translate(y, dot_dash_trans)), morse_table.items())
   translated_morse_table = dict(translated_morse_table)
   output = []
   for char in text.lower():
      if char in string.lowercase + string.digits:
         output.append(translated_morse_table[char])
   return space.join(output)
   
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

def break_columnar_transposition(ciphertext, pt_freq_table=frequency.frequency_tables['single_english'], num_answers=1):
   '''Uses brute force and plaintext detection to break columnar transposition'''
   results = {}
   ciphertext_len = len(ciphertext)
   for num_cols in range(2,ciphertext_len/2):
      result = ''.join([ciphertext[num::num_cols] for num in xrange(num_cols)])
      results[result] = detect_plaintext(result, pt_freq_table=pt_freq_table, detect_words=True)
   return sorted(results.items(),key=operator.itemgetter(1))[:num_answers]



def to_char(number):
   return chr(number + ord('A'))

def to_number(character):
   return ord(character) - ord('A')

def ind_of_coinc(text, distance):
   # Cut list to length which is divisible through distance
   length = len(text)
   cutting = length % distance
   text = text[:length-cutting]
   # Initialize frequency list
   freq = [[0 for i in xrange(26)] for i in xrange(distance)]
   times = len(text)/distance
   if times == 1:
      # So called one time pad -> no chance!
      return 0
   ioc = [0]*distance
   for offset in xrange(distance):
      # Build a frequency table for each offset
      for i in xrange(times):
         freq[offset][to_number(text[i*distance+offset])] += 1
      # Calculate index of coincidence for each offset
      for f in freq[offset]:
         ioc[offset] += f*(f-1.0) / (times*(times-1.0))
   # Take the average over all processed offsets
   ioc_total = 0.0
   for i in ioc:
      ioc_total += i

   # Alternative: distance to reference index of coincidence of 0.065 (for english language)
   #ioc_total = 0
   #for i in ioc:
   #    ioc_total += (i-0.065)**2
   #return 1/ioc_total*len(ioc)
   return ioc_total/len(ioc)

def translate_vigenere(text, key, decrypt):
   result = []
   key_index = 0
   key = key.upper()

   for c in text:
      number = string.ascii_uppercase.find(c.upper())
      if number == -1:
         # Character not alphabetic -> skip encryption/decryption
         result.append(c)
      else:
         current_shift = string.ascii_uppercase.find(key[key_index])
         new_number = (number + (-current_shift if decrypt else current_shift)) % len(string.ascii_uppercase)
         result.append(string.ascii_lowercase[new_number] if c.islower() else string.ascii_uppercase[new_number])
         key_index = (key_index + 1) % len(key)

   return "".join(result)

def evaluate_vigenere_key_length(ciphertext, max_length):
   # Calculate the index of coincidence for every key length assumption
   ioc_list = []
   for length in xrange(1, min(max_length+1, len(ciphertext))):
      ioc_list.append(ind_of_coinc(ciphertext, length))

   # Check if we possibly caught a multiple of the actual key length:
   # subtract median from every index of coincidence and square
   ioc_median = sorted(ioc_list)
   ioc_median = ioc_median[len(ioc_list)/2]
   ioc_contrast = [(x > ioc_median)*(x - ioc_median)**2 for x in ioc_list]

   # Look at the peaks
   ioc_sorted = sorted(list(enumerate(ioc_contrast, start=1)), key=lambda tup: tup[1], reverse=True)
   ioc_best_guesses = filter(lambda tup: tup[1] > 0.15*max(ioc_contrast), ioc_sorted)
   key_length_best_guesses = map(list, zip(*ioc_best_guesses))[0]
   key_length = key_length_best_guesses[0]

   # If a divisor of the guessed key length is also possible -> pick that one!
   repeat = True
   while repeat:
      repeat = False
      for divisor in xrange(2, int(sqrt(max_length))):
         if key_length % divisor == 0 and key_length / divisor in key_length_best_guesses:
            # Found a reasonable divisor -> key length can be reduced
            key_length /= divisor
            # With new key length: repeat process until no reasonable divisors are left
            repeat = True
            break

   # Change priority order if neccessary
   if not key_length == key_length_best_guesses[0]:
      key_length_best_guesses.remove(key_length)
      key_length_best_guesses.insert(0, key_length)

   return key_length_best_guesses

def break_shift(ciphertext, ref_letter_freq, correlation = False):
   # TODO: include / merge this code with the Cryptanalib break_alpha_shift() in the classical.py module
   # Measure letter frequency
   n = float(len(ciphertext))
   freq = [0]*26
   for symbol in ciphertext:
      freq[to_number(symbol)] += 1
   freq = [i/n for i in freq]

   shifts = []
   # Perform frequency analysis
   if correlation:
      # Break shift cipher by cross correlation with reference frequency
      cross_correlation = [sum([ref_letter_freq[i]*freq[(i+shift) % 26] for i in xrange(26)]) for shift in xrange(26)]
      # Sort the shift guesses by descending correlation value
      shifts = sorted(list(enumerate(chi_square_shifts)), key=lambda tup: tup[1], reverse=True)
   else:
      # Break shift cipher by chi-square like comparison of distribution with reference
      chi_square_quantile = 52.62
      chi_square_shifts = []
      for shift in xrange(26):
         chi_square = []
         for k in xrange(26):
            chi_square.append((freq[(k+shift) % 26] - ref_letter_freq[k])**2 / ref_letter_freq[k])
         chi_square_shifts.append(n*sum(chi_square))
      # Sort the shift guesses by ascending chi square value
      shifts = sorted(list(enumerate(chi_square_shifts)), key=lambda tup: tup[1])
      shifts = [(to_char(tup[0]),tup[1]) for tup in shifts]

      # Filter out the best few
      shifts_trunc = list(shifts)
      for k in xrange(len(shifts)-1):
         if shifts[k+1][1] < 50:
            continue
         elif shifts[k+1][1] / shifts[k][1] > 1.6:
            # If the step from this chi square value to the next higher one is too big,
            # export only the list up to this value.
            shifts_trunc = shifts[:k+1]
            break

   return zip(*shifts_trunc)[0]

def count_up(ll_indices, list_of_lists):
   digit = 0
   for digit in xrange(len(ll_indices)):
      # For every digit: start increasing the left most
      ll_indices[digit] += 1
      if ll_indices[digit] < len(list_of_lists[digit]):
         # As soon as no carry overflow happens: stop increasing
         return ll_indices
      else:
         # Carry overfow to the next digit
         ll_indices[digit] = 0
         digit += 1
         continue
   # If all digits were cycled through, return None as stop sequence
   return None

def break_vigenere(ciphertext, scan_range, num_answers=1, max_best_shifts=2,
               num_key_lengths=1, letter_frequency=frequency.frequency_tables['english_icase_letters'],
               num_key_guesses=100, coefficient_char_deviation=0, coefficient_word_count=1):

   # First strip cipher from non-alphabetical characters, convert to upper
   ciphertext = filter(lambda x: x.isalpha(), ciphertext).upper()

   # This module has had issues dealing with short ciphertexts, and it's
   # statistically super unlikely to solve ciphertexts short enough to cause
   # it issues. Reject any ciphertexts less than 10 characters in length.
   if len(ciphertext) < 10:
      print '[*] Skipping sample, too short to solve statistically'
      return False

   # Determine the key length
   key_lengths = evaluate_vigenere_key_length(ciphertext, scan_range)[:num_key_lengths]

   # Blockwise frequency analysis:
   # Preparation for fast break_shift function: sort out single char probabilities
   ref_letter_freq = [letter_frequency[k] for k in list(string.ascii_lowercase)]
   keys = {}

   #  Quick pre-sorting of the keys by single letter frequency analysis
   for key_length in key_lengths:
      # For every key_length guess in the list:
      # cut list to length which is divisible through the key length
      sub_blocks = [[ciphertext[i+j*key_length] for j in xrange(0,int(len(ciphertext)/key_length))] for i in xrange(0,key_length)]

      # For every digit in the key (whose length we have now guessed), use an ascii shift cipher breaker
      # against all subblocks consisting of every k-th letter with k = key_length
      digits_shifts = []
      for i,sub_block in enumerate(sub_blocks):
         # Apply shift breaker. That one works on letter frequency analysis and returns
         # a list of the most likely shift guesses.
         shifts = break_shift(sub_block, ref_letter_freq, False)
         digits_shifts.append(shifts[:min(len(shifts), max_best_shifts)])

      # Out of these shift guesses, construct all possible combinations of complete keys
      digit_shift_index = [0]*key_length
      while True:
         # Construct keys from different shift possibilities for each digit
         current_key =  "".join([digits_shifts[digit][digit_shift_index[digit]] for digit in xrange(len(digits_shifts))])

         # If more than one key lengths were guessed:
         if len(key_lengths) > 1 and key_length == min(key_lengths):
            # At the smallest key length: don't pre-sort and score theses, the more advanced multigraph and word
            # analysis further down will be quick on them -> just add them to the top of the list straight away.
            keys[current_key] = 0
         else:
            # Perform an encryption with this possible key and score its plaintext with single letter frequency
            plaintext = translate_vigenere(ciphertext, current_key, decrypt=True)
            keys[current_key] = detect_plaintext(plaintext.lower(), detect_words=False)

         if count_up(digit_shift_index, digits_shifts) == None:
            break
   keys_sorted_by_single_letter_score = sorted(keys.items(), key=operator.itemgetter(1))

   # Now do a more advanced analysis on plaintext detection, this time additionally with
   # multigraph frequency analysis and common word count -> this is very slow but more accurate
   keys2 = []
   for (current_key,score) in keys_sorted_by_single_letter_score[:num_key_guesses]:
      plaintext = translate_vigenere(ciphertext, current_key, decrypt=True)
      keys2.append((current_key, detect_plaintext(plaintext.lower(), detect_words=(coefficient_word_count!=0.0), individual_scores=True)))

   # weighting the different detect_plaintext analysis and sort the list
   weighting = lambda x: coefficient_char_deviation*x[1][0] + coefficient_word_count*x[1][1]
   keys_by_combinations = sorted(keys2, key=weighting)

   # strip list from score
   key_list = list(zip(*keys_by_combinations)[0])

   # Deal with possible key multiplication (eg. "SECRETSECRET" instead of "SECRET")
   if len(key_list) > 1:
      first_len = len(key_list[0])
      second_len = len(key_list[1])
      if first_len != second_len and first_len % second_len == 0:
         if key_list[1] == key_list[0][:second_len]:
            key_list.remove(key_list[1])

   return key_list[:num_answers]

