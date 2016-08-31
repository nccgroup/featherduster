from math import sqrt
import operator
import string
import frequency

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
english_letter_frequency = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
file_debug = False

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
        number = alphabet.find(c.upper())
        if number == -1:
            # Character not alphabetic -> skip encryption/decryption
            result.append(c)
        else:
            current_shift = alphabet.find(key[key_index])
            new_number = (number + (-current_shift if decrypt else current_shift)) % len(alphabet)
            result.append(alphabet[new_number].lower() if c.islower() else alphabet[new_number])
            key_index = (key_index + 1) % len(key)

    return "".join(result)

def evaluate_vigenere_key_length(ciphertext, max_length):
    # Calculate the index of coincidence for every key length assumption 
    ioc_list = []
    for length in xrange(1, min(max_length+1, len(ciphertext))):
        ioc_list.append(ind_of_coinc(ciphertext, length))
    
    if file_debug:
        f = open('length_analysis.txt', 'w')
        f.write(" ".join(str(i) for i in ioc_list))
        f.close()

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

        #if shifts[0][1] < chi_square_quantile:
        #    # if there are several guesses with a reasonable chi square test value:
        #    # accept them until a quantil of 99.0% and strip the chi square score off
        #    shifts_filtered = zip(*filter(lambda tup: tup[1] < chi_square_quantile, shifts))[0]
        #else:
        #    # if they're all pretty poor, just return the best possible shift
        #    shifts_filtered = [shifts[0][0]]

    if file_debug:
        f = open('freq_analysis.txt', 'w')
        f.write(" ".join(str(i) for i in ref_letter_freq) + "\n")
        f.write(" ".join(str(i) for i in cross_correlation) + "\r\n")
        f.close()
    
    return zip(*shifts_trunc)[0]

def detect_plaintext(candidate_text, pt_freq_table=frequency.frequency_tables['english_icase_letters'], common_words=frequency.common_words['english'], detect_single_letters=True, detect_multigraphs=True, detect_words=True):
    score_single_letter = 0
    score_multigraph = 0
    score_words = 0
    
    if detect_single_letters:
        # Measure letter frequency
        freq = [0]*26
        for symbol in candidate_text.upper():
            freq[to_number(symbol)] += 1
        freq = [i/float(len(candidate_text)) for i in freq]

        comparison_method = 'correlation'
        if comparison_method == 'chi_square':
            # Generate score as deviation from expected character frequency (in a chi-square like manner)
            score = 0.0
            for k in xrange(26):
                score += (freq[(k)] - english_letter_frequency[k])**2 / english_letter_frequency[k]
            score *= len(candidate_text)
        elif comparison_method == 'correlation':
            score = 0.0
            for k in xrange(26):
                score += freq[(k)] * english_letter_frequency[k]
            score = 1.0/score
        else:
            score = 0.0
            for k in xrange(26):
                score += abs(freq[(k)] - english_letter_frequency[k])
        score_single_letter = score
    if detect_multigraphs:
        pt_freq_table_keys = pt_freq_table.keys()
        candidate_dict = generate_frequency_table(candidate_text, pt_freq_table_keys)
        
        score = 0.0
        
        for multigraph in pt_freq_table_keys:
            #TODO: how to deal with multigraphs that have a probability of 0.0?
            if pt_freq_table[multigraph] == 0.0:
                # If that multigraph isn't even allowed, add a empirical high value to the score
                #if candidate_dict[multigraph] != 0:
                    #score += candidate_dict[multigraph]*50
                pass
            else:
                score += (candidate_dict[multigraph]-pt_freq_table[multigraph])**2 / pt_freq_table[multigraph]
        score_multigraph = score
    if detect_words:
        score_words = 1
        count = 0
        for word in common_words:
            count += candidate_text.count(word.lower())*len(word)
        if count == 0:
            count = 0.5
        score_words = len(candidate_text) / float(count)
    return (score_single_letter, score_multigraph, score_words)

def generate_frequency_table(text,charset):
    freq_table = {}
    text_len = 0 
    for char in charset:
        freq_table[char] = 0 
    for multigraph in charset:
        freq_table[multigraph] = string.count(text, multigraph)
        text_len += freq_table[multigraph]
    # Normalize frequencies with length of text
    for key in freq_table.keys():
        if text_len != 0:
            freq_table[key] /= float(text_len)
        else:
            freq_table[key] = 0 
    return freq_table

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
                   num_key_lengths=1, ref_letter_freq=english_letter_frequency,
                   coefficient_single_letter=0, coefficient_multigraph=0, coefficient_word_count=1):
    # First strip cipher from non-alphabetical characters, convert to upper
    ciphertext = filter(lambda x: x.isalpha(), ciphertext).upper()

    # Determine the key length
    key_lengths = evaluate_vigenere_key_length(ciphertext, scan_range)[:num_key_lengths]

    # Prepare for blockwise frequency analysis:
    origin_frequency_table = frequency.frequency_tables['english_icase_letters']
    digraph_charset = dict((k,origin_frequency_table[k]) for k in origin_frequency_table if len(k) > 1)
    # Only take words with three or more letters
    # (all two letter words were already covered in the digraph charset)
    origin_common_words = frequency.common_words['english']
    common_words_set = [k for k in origin_common_words if len(k) > 2]
    keys = {}

    #  Now comes a quick pre-sorting of the keys by single letter frequency analysis
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
        
        # Out of these shift guesses, construct all possible compinations of complete keys
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
                
                detect_single_letters = False if coefficient_single_letter == 0 else True
                detect_multigraphs = False if coefficient_multigraph == 0 else True
                detect_words = False if coefficient_word_count == 0 else True
                
                keys[current_key] = detect_plaintext(plaintext.lower(),
                                    detect_single_letters=detect_single_letters,
                                    detect_multigraphs=detect_multigraphs,
                                    detect_words=detect_words)[0]
            
            if count_up(digit_shift_index, digits_shifts) == None:
                break
    keys_sorted_by_single_letter_score = sorted(keys.items(), key=operator.itemgetter(1))

    # Now do a more advanced analysis on plaintext detection, this time additionally with
    # multigraph frequency analysis and common word count -> this is very slow but more accurate
    keys2 = []
    for (current_key,score) in keys_sorted_by_single_letter_score[:100]:
        plaintext = translate_vigenere(ciphertext, current_key, decrypt=True)
        keys2.append((current_key, detect_plaintext(plaintext.lower(),
                     detect_single_letters=True, detect_multigraphs=True, detect_words=True)))

    # weighting the different detect_plaintext analysis and sort the list
    weighting = lambda x: coefficient_single_letter*x[1][0] + coefficient_multigraph*x[1][1] + coefficient_word_count*x[1][2]
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

