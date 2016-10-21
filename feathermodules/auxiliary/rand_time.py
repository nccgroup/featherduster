import cryptanalib as ca
import feathermodules
from time import time
import random

def rand_seeded_with_time_check(samples):
   def seed_and_generate_value(seed, lowest, highest):
      random.seed(seed)
      return random.randint(lowest, highest)
   
   options = feathermodules.current_options
   options_tmp = dict(options)
   check_arguments(options_tmp)
   if options_tmp == False:
      return False
   timestamps = range(options_tmp['base_timestamp']-86400,options_tmp['base_timestamp']+86400)

   prng_outputs = map(lambda timestamp: seed_and_generate_value(timestamp, options_tmp['lowest'], options_tmp['highest']), timestamps)
   converted_samples = map(lambda sample: int(sample, options_tmp['base']), samples)
   matches = set(prng_outputs) & set(converted_samples)
   if matches:
      print '[!] %d matches were discovered! This suggests random outputs are based on Mersenne Twister output seeded with the current system time.' % len(matches)
      return matches
   else:
      print '[+] No matches discovered.'
      return False
         
      

def check_arguments(options):
   try:
      print '[+] Checking provided timestamp...'
      options['base_timestamp'] = int(options['base_timestamp'])
      print '[+] Checking provided format...'
      if options['format'].lower() in ['hex', 'h']:
         options['base'] = 16
      elif options['format'].lower() in ['dec', 'd', 'decimal']:
         options['base'] = 10
      else:
         print '[*] Format option was not recognized. Please use \'hex\' or \'dec\'.'
      print '[+] Checking lowest possible value...'
      options['lowest'] = int(options['lowest'], options['base'])
      print '[+] Checking highest possible value...'
      options['highest'] = int(options['highest'], options['base'])
      return options
   except:
      print '[*] One or more numeric arguments could not be converted to a number. Please try again.'
      return False 


feathermodules.module_list['rand_time'] = {
   'attack_function':rand_seeded_with_time_check,
   'type':'auxiliary',
   'keywords':['random'],
   'description':'A brute force attack attempting to match captured samples to the output of the Mersenne Twister PRNG seeded with the current system time.',
   'options':{'base_timestamp': str(int(time())),
      'format': 'hex',
      'lowest': '00000000',
      'highest': 'FFFFFFFF'
   }
}

