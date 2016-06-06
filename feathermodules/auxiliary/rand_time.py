import cryptanalib as ca
import feathermodules
from time import time
import random

def rand_seeded_with_time_check(samples):
   def seed_and_generate_value(seed, lowest, highest):
      random.seed(seed)
      return random.randint(lowest, highest)
   
   arguments = get_arguments()
   prng_outputs = map(lambda timestamp: seed_and_generate_value(timestamp, arguments['lowest_value'], arguments['highest_value']), arguments['timestamps'])
   converted_samples = map(lambda sample: int(sample, arguments['base']), samples)
   matches = set(prng_outputs) & set(converted_samples)
   if matches:
      print '[!] %d matches were discovered! This suggests random outputs are based on Mersenne Twister output seeded with the current system time.' % len(matches)
   else:
      print '[+] No matches discovered.'
         
      
sample_format_menu = """Which format are the samples in?

1) Hex (i.e. 4e813eef)
2) Decimal (i.e. 971412412)

Please enter a number: """

def get_arguments():
   arguments = {}
   use_current_time = raw_input('Do you want to use the current time (yes)? ')
   if use_current_time.lower() in ['y','yes','']:
      base_timestamp = int(time())
   else:
      base_timestamp = raw_input('Please enter a time in Unix timestamp format: ')
      try:
         base_timestamp = int(base_timestamp)
      except ValueError:
         print 'Bad timestamp value. Defaulting to current time.'
         base_timestamp = int(time())
   arguments['timestamps'] = range(base_timestamp-86400,base_timestamp+86400)
   while True:
      sample_format = raw_input(sample_format_menu)
      if sample_format == '1':
         arguments['base'] = 16
         break
      elif sample_format == '2':
         arguments['base'] = 10
         break
      else:
         print 'Sorry, your input was not recognized. Please try again.'
         continue
   while True:
      lowest = raw_input('Please enter the lowest possible value a sample could be (for example, if samples are in hex format and can be between 0x00000000 and 0xffffffff, enter "00000000"): ')
      try:
         arguments['lowest_value'] = int(lowest, arguments['base'])
         break
      except ValueError:
         print 'Bad value received. Try again.'
         continue
   while True:
      highest = raw_input('Please enter the highest possible value a sample could be (for example, if samples are in hex format and can be between 0x00000000 and 0xffffffff, enter "FFFFFFFF"): ')
      try:
         arguments['highest_value'] = int(highest, arguments['base'])
         break
      except ValueError:
         print 'Bad value received. Try again.'
         continue
   return arguments


feathermodules.module_list['rand_time'] = {
   'attack_function':rand_seeded_with_time_check,
   'type':'auxiliary',
   'keywords':['random'],
   'description':'A brute force attack attempting to match captured samples to the output of the Mersenne Twister PRNG seeded with the current system time.',
   'options':{}
}

