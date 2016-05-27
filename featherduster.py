'''
FeatherDuster - A wizard-like interface to cryptanalib
Author: Daniel Crowley

FeatherDuster is a tool for brushing away magical crypto fairy dust.
'''

import sys
import glob
from ishell.console import Console
from ishell.command import Command

import feathermodules
from feathermodules.stream import *
from feathermodules.block import *
from feathermodules.classical import *
from feathermodules.auxiliary import *
from feathermodules.custom import *
from feathermodules.pubkey import *

import cryptanalib as ca

feathermodules.samples = []
feathermodules.selected_attack = ''

# import
class ImportMultiFileCommand(Command):
   def run(self, line):
      # TODO: open a subconsole or just use readline to get filename w tab complete
      sample_file = raw_input('Please enter the filename you want to open: ')
      try:
         sample_fh = open(sample_file,'r')
         feathermodules.samples.extend([sample.strip() for sample in sample_fh.readlines()])
         sample_fh.close()
         feathermodules.samples = filter(lambda x: x != '' and x != None, feathermodules.samples)
      except:
         print 'Something went wrong. Sorry! Please try again.'

class ImportSingleFileCommand(Command):
   def run(self, line):
      # TODO: open a subconsole or just use readline to get filename w tab complete
      sample_file = raw_input('Please enter the filename you want to open: ')
      try:
         sample_fh = open(line.split()[-1],'r')
         feathermodules.samples.append(sample_fh.read())
         sample_fh.close()
      except:
         print 'Something went wrong. Sorry! Please try again.'

class ImportManualEntryCommand(Command):
   def run(self, line):
      feathermodules.samples.append(raw_input('Please enter your sample: ').strip())

class ImportClearCommand(Command):
   def run(self, line):
      feathermodules.samples = []

class ImportCommand(Command):
   def args(self):
      return ['multifile', 'singlefile', 'manualentry', 'clear']

import_sample = ImportCommand('import', help='Import samples for analysis', dynamic_args=True)

import_multifile = ImportMultiFileCommand(
   'multifile',
   help='Import multiple newline-separated samples from one file',
   dynamic_args=True)
import_singlefile = ImportSingleFileCommand(
   'singlefile',
   help='Import a single file as a raw sample',
   dynamic_args=True)
import_manualentry = ImportManualEntryCommand(
   'manualentry',
   help='Manually enter a single sample',
   dynamic_args=True)
import_clear = ImportClearCommand(
   'clear',
   help='Clear current sample set',
   dynamic_args=True)

import_sample.addChild(import_multifile)
import_sample.addChild(import_singlefile)
import_sample.addChild(import_manualentry)
import_sample.addChild(import_clear)

# use
class UseCommand(Command):
   def args(self):
      return feathermodules.module_list.keys()
   def run(self, line):
      if line.split()[-1] not in feathermodules.module_list.keys():
         print 'Invalid module selection. Please try again.'
      else:
         feathermodules.selected_attack = line.split()[-1]

use = UseCommand('use', help='Select the module to use', dynamic_args=True)

# analyze
class AnalyzeCommand(Command):
   def run(self, line):
      if len(feathermodules.samples) == 0:
         print 'No loaded samples. Please use the \'import\' command.'
         return False
      print '[+] Analyzing samples...'
      analysis_results = ca.analyze_ciphertext(feathermodules.samples, verbose=True, do_more_checks=True)
      if analysis_results['decoded_ciphertexts'] != feathermodules.samples:
         feathermodules.samples = analysis_results['decoded_ciphertexts']
      print ''
      print '[+] Suggested modules:'
      for attack in feathermodules.module_list.keys():
         if len(set(feathermodules.module_list[attack]['keywords']) & set(analysis_results['keywords'])) > 0:
            print "%s - %s" % (attack, feathermodules.module_list[attack]['description'])
   
analyze = AnalyzeCommand('analyze', help='Analyze/decode samples', dynamic_args=True)


# autopwn
class AutopwnCommand(Command):
   def run(self, line):
      if len(feathermodules.samples) == 0:
         print 'No loaded samples. Please use the \'import\' command.'
         return False
      print '[+] Analyzing samples...'
      analysis_results = ca.analyze_ciphertext(feathermodules.samples, verbose=True, do_more_checks=True)
      if analysis_results['decoded_ciphertexts'] != feathermodules.samples:
         feathermodules.samples = analysis_results['decoded_ciphertexts']
      for attack in feathermodules.module_list.keys():
         if len(set(feathermodules.module_list[attack]['keywords']) & set(analysis_results['keywords'])) > 0:
            print feathermodules.module_list[attack]['attack_function'](feathermodules.samples)
   
autopwn = AutopwnCommand('autopwn', help='Analyze samples and run all attacks', dynamic_args=True)


# search
class SearchCommand(Command):
   def run(self, line):
      matching_modules = []
      search_param = line.split()[-1].lower()
      for attack in feathermodules.module_list.keys():
         if attack.lower().find(search_param) != -1:
            matching_modules.append(attack)
         elif feathermodules.module_list[attack]['description'].lower().find(search_param) != -1:
            matching_modules.append(attack)
         elif search_param in feathermodules.module_list[attack]['keywords']:
            matching_modules.append(attack)
      for module in matching_modules:
         print "%s - %s" % (module, feathermodules.module_list[module]['description'])
      
search = SearchCommand('search', help='Search module names and descriptions by keyword')


# samples
class SamplesCommand(Command):
   def run(self, line):
      print '-' * 40
      for sample in feathermodules.samples:
         print repr(sample)
      print '-' * 40

samples = SamplesCommand('samples', help='Show samples')


# modules
class ModulesCommand(Command):
   def run(self, line):
      for attack in feathermodules.module_list.keys():
         print "%s - %s" % (attack, feathermodules.module_list[attack]['description'])

modules = ModulesCommand('modules', help='Show all available modules')


# run
class RunCommand(Command):
   def run(self, line):
      if len(feathermodules.samples) == 0:
         print 'No loaded samples. Please use the \'import\' command.'
         return False
      if feathermodules.selected_attack not in feathermodules.module_list.keys():
         print 'Invalid module selection. Please use the \'use\' command.'
         return False
      print feathermodules.module_list[feathermodules.selected_attack]['attack_function'](feathermodules.samples)

run = RunCommand('run', help='Run the currently selected module')


# options
class OptionsCommand(Command):
   # TODO: Eventually, migrate option selection out of feathermodules and into FD itself
   def run(self, line):
      print 'Currently selected module: %s' % feathermodules.selected_attack

options = OptionsCommand('options', help='Show current configuration options', dynamic_args=True)

# Build the console
fd_console = Console(prompt='\nFeatherDuster', prompt_delim='>')

fd_console.addChild(import_sample)
fd_console.addChild(use)
fd_console.addChild(analyze)
fd_console.addChild(autopwn)
fd_console.addChild(search)
fd_console.addChild(samples)
fd_console.addChild(modules)
fd_console.addChild(run)
fd_console.addChild(options)


#--------
# Main menu
#
print 'Welcome to FeatherDuster!\n'

for filename in sys.argv[1:]:
   sample_file = filename
   sample_fh = open(sample_file,'r')
   feathermodules.samples.append(sample_fh.read())
   sample_fh.close()

fd_console.loop()

print '\nThank you for using FeatherDuster!'
