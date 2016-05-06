'''
FeatherDuster - A wizard-like interface to cryptanalib
Author: Daniel Crowley

FeatherDuster is a tool for brushing away magical crypto fairy dust.
'''

import sys
import string

import feathermodules
from feathermodules.stream import *
from feathermodules.block import *
from feathermodules.classical import *
from feathermodules.auxiliary import *
from feathermodules.custom import *
from feathermodules.pubkey import *

import cryptanalib as ca

#--------
# Helper functions
#
import_selection_prompt = """
Please select one of the following options:
1) Import multiple newline-separated samples from a file
2) Import a file as a single sample
3) Manually enter a single sample
q) Quit

Your selection: """
def import_samples():
   selection = ''
   while selection not in ['1','2','3','q']:
      selection = raw_input(import_selection_prompt).strip().lower()

      if selection == 'q':
         print 'Thanks for using FeatherDuster!'
         exit(0)

      elif selection == '1':
         print 'For best results, provide a file with base64 or hex encoded samples separated by newlines.'
         ciphertext_file = raw_input('Please enter the name of the file: ')
         try:
            sample_fh = open(sample_file,'r')
            samples = [sample.strip() for sample in sample_fh.readlines()]
            sample_fh.close()
            samples = filter(lambda x: x != '' and x != None, samples)
         except:
            print 'Something went wrong. Sorry! Please try again.'
            selection = 'failure'

      elif selection == '2':
         sample_file = raw_input('Please enter the name of the file: ')
         try:
            sample_fh = open(sample_file,'r')
            samples = [sample_fh.read()]
            sample_fh.close()
         except:
            print 'Something went wrong. Sorry! Please try again.'
            selection = 'failure'
         
      elif selection == '3':
         samples = [raw_input('Please enter your ciphertext: ')]

      else:
         print 'Sorry, your selection wasn\'t recognized.'

   return samples

attack_selection_prompt = """
How do you want to select attacks to run?

a) Analyze samples
m) Manual selection, skip analysis
s) Search for a module
p) Crypto autopwn
b) Go back
q) Quit

Please enter your choice: """
def get_attack_selection_method():
   attack_selection = ''
   while True:
      attack_selection = raw_input(attack_selection_prompt).strip().lower()
      if attack_selection in ['a', 'm', 's', 'p', 'b']:
         return attack_selection
      elif attack_selection == 'q':
         print 'Thanks for using FeatherDuster!'
         exit(0)
      else:
         print 'Sorry, your input was not recognized. Please try again.'

   
#
#--------

#--------
# Main menu
#
print 'Welcome to FeatherDuster!'

while True:
   no_more = False
   samples = []
   while no_more == False:
      if len(sys.argv) >= 2:
         for filename in sys.argv[1:]:
            sample_file = filename
            sample_fh = open(sample_file,'r')
            samples.append(sample_fh.read())
         sys.argv = []
      else:
         samples.extend(import_samples())
      if raw_input('Would you like to enter additional samples (y/N)?').lower() not in ['y','yes']:
         no_more = True 

   # Build module list
   attack_selection_method = get_attack_selection_method()
   if attack_selection_method == 'b':
      continue
   elif attack_selection_method in ['a', 'p']:
      print '[+] Analyzing samples...'
      analysis_results = ca.analyze_ciphertext(samples, verbose=True, do_more_checks=True)
      print ''
      if analysis_results['decoded_ciphertexts'] != samples:
         samples = analysis_results['decoded_ciphertexts']
         if raw_input('The imported samples were encoded. Do you want to show the decoded samples (no)? ').lower() in ['y','yes']:
            print 'Samples:\n' + '-'*40
            for sample in samples:
               print repr(sample)
            print '-'*40 + '\n'
   elif attack_selection_method == 's':
      search_term = raw_input("Please enter your search term: ")
      

   # Present attack options
   selected_attack = ''
   while selected_attack.lower() not in ['back', 'b']:
      attacks = feathermodules.module_list.keys()
      if attack_selection_method in ['a', 'p']:
         attacks_tmp = []
         for attack in attacks:
            if len(set(feathermodules.module_list[attack]['keywords']) & set(analysis_results['keywords'])) > 0:
               attacks_tmp.append(attack)
         attacks = attacks_tmp
      elif attack_selection_method == 's':
         attacks_tmp = []
         for attack in attacks:
            keyword_match = False
            for keyword in feathermodules.module_list[attack]['keywords']:
               if string.find(keyword, search_term) >= 0:
                  attacks_tmp.append(attack)
                  keyword_match = True
                  break 
            if keyword_match:
               continue
            elif string.find(feathermodules.module_list[attack]['description'], search_term) >= 0:
               attacks_tmp.append(attack)
            elif string.find(attack, search_term) >= 0:
               attacks_tmp.append(attack)

         attacks = attacks_tmp
      if len(attacks) == 0:
         print 'No applicable attack modules are available.'
         break
      else:
         print 'Attack modules:'

      if attack_selection_method == 'p':
         print 'Starting crypto autopwn. BANZAIIIIIII!!!'
         for attack in attacks:
            print "Launching attack module: %s" % attack
            print feathermodules.module_list[attack]['attack_function'](samples)
            print ''
         break

      else:
         for attack in attacks:
            print "%s - %s" % (attack, feathermodules.module_list[attack]['description'])
         while True:
            selected_attack = raw_input('Choose an attack from the listing above or type \'back\' or \'quit\': ')
            if selected_attack in ['b','back']:
               break
            if selected_attack in ['q','quit']:
               print 'Thanks for using FeatherDuster!'
               exit(0)
            if selected_attack in feathermodules.module_list.keys():
               print feathermodules.module_list[selected_attack]['attack_function'](samples)
            else:
               print 'Sorry, I don\'t see this module in the list. Please try again.'
            print ''
