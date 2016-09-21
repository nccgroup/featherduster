import cryptanalib as ca
from random import seed, randint
from datetime import datetime
import cProfile
import time
import sys

# Parameters
plaintext_len_min = 50
plaintext_len_step = 25
plaintext_len_max = 400
key_len_min = 5
key_len_step = 1
key_len_max = 10
key_len_max_try = 11
iterations = 5
max_best_shifts = 2
num_key_lengths = 3
num_key_guesses = 100

textfile = open('english_text.txt', 'r')
english_text = filter(lambda x: x.isalpha(), textfile.read()).upper()
textfile.close()

def update_progress(progress, status = "", done = ""):
    barLength = 20 # Modify this to change the length of the progress bar
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = done + "\r\n"
    block = int(round(barLength*progress))
    text = "\rProgress: [{0}] {1:.1f}% {2}".format( "#"*block + " "*(barLength-block), progress*100, status)
    sys.stdout.write(text)
    sys.stdout.flush()

def test_run(plaintext_len, key_len, key = ""):
    # generate plaintext
    random_start = randint(0, len(english_text)-plaintext_len-1)
    plaintext = english_text[random_start:random_start+plaintext_len]
                
    # generate key
    if key == "":
        key = "".join(ca.to_char(randint(0,25)) for i in xrange(key_len))
    #print 'Random key:', key
    # apply encryption and decryption
    #print "plaintext length:", plaintext_len, ", key length:", key_len
    ciphertext = ca.translate_vigenere(plaintext, key, 0)
    key_guesses = ca.break_vigenere(ciphertext, key_len_max_try, num_key_guesses=num_key_guesses,num_answers=1, max_best_shifts=max_best_shifts, num_key_lengths=num_key_lengths)
    key_guess = key_guesses[0]

    score = 0.0
    plaintext_guess = ca.translate_vigenere(ciphertext, key_guess, 1)
                
    # evaluate result of key guess
    if key_guess == key:
        #print "  perfect match!"
        score = 1.0
    else:
        if len(key_guess) == len(key):
            # calculate score of revealed key
            score = 0.0
            for (i, symbol) in enumerate(key_guess):
                if symbol == key[i]:
                    score += 1
            score /= float(len(key))
            #print "  Length is correct, key is recovered %d/%d" % (key_score, len(key))
        elif len(key_guess) % len(key) == 0:
            #print "  Multiple of the key lenght: %d instead of %d" % (len(key_guess), len(key))
            pass
        else:
            score = 0.0
        # calculate score over whole encrypted plaintext
        #score = 0.0
        #for (i, symbol) in enumerate(plaintext_guess):
        #    if symbol == plaintext[i]:
        #        score += 1
        #score /= float(len(plaintext))

        #print "  score:", score
    return score

def testbench():
    plaintext_iter = xrange(plaintext_len_min, plaintext_len_max+plaintext_len_step, plaintext_len_step)
    key_len_iter = xrange(key_len_min, key_len_max+key_len_step, key_len_step)
    result = [[]]
    total_progress = len(plaintext_iter)*len(key_len_iter)*iterations
    progress = 0
    average_time = 0

    time_file = open('testbench_times.txt', 'w')

    print "Running Testbench"
    start_time = datetime.now()

    result.append([0] + list(key_len_iter))
    
    for plaintext_len in plaintext_iter:
        same_plaintext_len_results = [plaintext_len]
        for key_len in key_len_iter:
            single_result = 0
            for iteration in xrange(iterations):
                start_run_time = time.time()
                score = test_run(plaintext_len, key_len)
                single_result += score
                end_run_time = time.time()
                time_file.write(str(end_run_time-start_run_time) + '\n')
                average_time += end_run_time - start_run_time

                progress += 1
                update_progress(progress/float(total_progress+1), status="keylength: %d, textlength: %d    " % (key_len, plaintext_len))

            same_plaintext_len_results.append(float(single_result)/iterations)
        result.append(same_plaintext_len_results)

    end_time = datetime.now()
    update_progress(1, done='Completed in %s hours             ' % str(end_time-start_time).rsplit('.')[0])
    print 'average time per break run: %.1f' % (average_time/total_progress)
    time_file.close()    
    with open('testbench.txt', 'w') as file:
        file.writelines('\t'.join(str(j) for j in i) + '\n' for i in result)
        file.close()

def testbench_key_length():
    plaintext_iter = xrange(plaintext_len_min, plaintext_len_max+plaintext_len_step, plaintext_len_step)
    key_len_iter = xrange(key_len_min, key_len_max+key_len_step, key_len_step)
    result = [[]]
    total_progress = len(plaintext_iter)*len(key_len_iter)*iterations
    progress = 0

    print "Running Testbench with key length only"
    start_time = datetime.now()

    result.append([0] + list(key_len_iter))
    
    for plaintext_len in plaintext_iter:
        same_plaintext_len_results = [plaintext_len]
        for key_len in key_len_iter:
            single_result = 0
            key_length_room = []
            for iteration in xrange(iterations):
                # generate plaintext
                random_start = randint(0, len(english_text)-plaintext_len-1)
                plaintext = english_text[random_start:random_start+plaintext_len]
                            
                # generate key
                key = "".join(ca.to_char(randint(0,25)) for i in xrange(key_len))
                # apply encryption and decryption
                #print "plaintext length:", plaintext_len, "key length:", key_len
                ciphertext = ca.translate_vigenere(plaintext, key, 0)
                key_length_guesses = evaluate_vigenere_key_length(ciphertext, key_len_max_try)
                key_length_guess = key_length_guesses[0]

                score = 0.0
                multiple = 0.0
                too_low = 0.0

                # evaluate result of key length guess
                if key_length_guess == len(key):
                    score = 1.0
                elif key_length_guess < len(key):
                    too_low = 1.0
                elif key_length_guess % len(key) == 0:
                    multiple = 1.0
                
                #if len(key) in key_length_guesses:
                #    score = 1.0
                
                single_result += score

                progress += 1
                update_progress(progress/float(total_progress + 1), status="k:%d p:%d g:%s     \n" % (key_len, plaintext_len, str(key_length_guesses)))

            same_plaintext_len_results.append(float(single_result)/iterations)
        result.append(same_plaintext_len_results)

    end_time = datetime.now()
    update_progress(1, 'completed in %s hours.' % str(end_time-start_time).rsplit('.')[0])
    with open('testbench.txt', 'w') as file:
        file.writelines('\t'.join(str(j) for j in i) + '\n' for i in result)
        file.close()
    raw_input("Press Enter to continue...")

################
#  PROFILING
################
#cProfile.run('test_run(100,5)')

#def loop():
#    for i in xrange(1000):
#        ca.translate_vigenere(ciphertext, "KRYPT", decrypt=True)
#cProfile.run('loop()')#, 'vigenere_stats.prof')


##################
#  TEST BENCHES
##################
#print test_run(100,5)
testbench()
#testbench_key_length()

raw_input("Press Enter to continue...")
