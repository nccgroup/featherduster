'''
FeatherDuster - A wizard-like interface to cryptanalib
Author: Daniel Crowley

FeatherDuster is a tool for brushing away magical crypto fairy dust.
'''

import sys
import os
import readline
import completer #readline completion
import advice #advice text
from ishell.console import Console
from ishell.command import Command

try:
   from IPython import embed
except ImportError:
   import code

   def embed():
      vars = globals()
      vars.update(locals())
      shell = code.InteractiveConsole(vars)
      shell.interact()

import feathermodules

feathermodules.samples = []
feathermodules.results = False
feathermodules.analysis_results = False
feathermodules.selected_attack_name = ''
feathermodules.current_options = {}

from feathermodules.stream import *
from feathermodules.block import *
from feathermodules.classical import *
from feathermodules.auxiliary import *
from feathermodules.custom import *
from feathermodules.pubkey import *

import cryptanalib as ca

# import
class ImportMultiFileCommand(Command):
   def run(self, line):
      ishellCompleter = readline.get_completer()
      readline.set_completer_delims(' \t\n;')
      readline.parse_and_bind("tab: complete")
      readline.set_completer(completer.complete)

      sample_file = raw_input('Please enter the filename you want to open: ')
      try:
         sample_fh = open(sample_file,'r')
         feathermodules.samples.extend([sample.strip() for sample in sample_fh.readlines()])
         sample_fh.close()
         feathermodules.samples = filter(lambda x: x != '' and x != None, feathermodules.samples)
      except:
         print 'Something went wrong. Sorry! Please try again.'
      finally:
         readline.set_completer(ishellCompleter)

class ImportSingleFileCommand(Command):
   def run(self, line):
      ishellCompleter = readline.get_completer()
      readline.set_completer_delims(' \t\n;')
      readline.parse_and_bind("tab: complete")
      readline.set_completer(completer.complete)

      sample_file = raw_input('Please enter the filename you want to open: ')
      try:
         sample_fh = open(sample_file,'r')
         feathermodules.samples.append(sample_fh.read())
         sample_fh.close()
         feathermodules.samples = filter(lambda x: x != '' and x != None, feathermodules.samples)
      except:
         print 'Something went wrong. Sorry! Please try again.'
      finally:
         readline.set_completer(ishellCompleter)

class ImportManualEntryCommand(Command):
   def run(self, line):
      feathermodules.samples.append(raw_input('Please enter your sample: ').strip())
      feathermodules.samples = filter(lambda x: x != '' and x != None, feathermodules.samples)


class ImportResultsCommand(Command):
   def run(self, line):
      if not feathermodules.results:
         print 'Last module failed to produce results.'
      elif feathermodules.results == True:
         print 'Last module succeeded, but did not return results.'
      else:
         print 'Last results (long values may be truncated):'
         print '-'*80
         for i in range(len(feathermodules.results)):
            print '{0:d}: {1:60s}'.format(i, repr(feathermodules.results[i]))
      
      selection = raw_input('\nPlease enter your selection by number, or \'all\' for all: ')
      try:
         if selection == 'all':
            feathermodules.samples.extend(feathermodules.results)
         elif int(selection) < len(feathermodules.results):
            feathermodules.samples.append(feathermodules.results[int(selection)])
         else:
            print 'Invalid entry, please try again.'
         feathermodules.samples = filter(lambda x: x != '' and x != None, feathermodules.samples)
      except ValueError:
         print 'Invalid entry, please try again.'
         

class ImportClearCommand(Command):
   def run(self, line):
      feathermodules.samples = []

class ImportCommand(Command):
   def args(self):
      return ['multifile', 'singlefile', 'manualentry', 'results', 'clear']

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
import_results = ImportResultsCommand(
   'results',
   help='Import last module\'s results as samples',
   dynamic_args=True)
import_clear = ImportClearCommand(
   'clear',
   help='Clear current sample set',
   dynamic_args=True)

import_sample.addChild(import_multifile)
import_sample.addChild(import_singlefile)
import_sample.addChild(import_manualentry)
import_sample.addChild(import_results)
import_sample.addChild(import_clear)



# advice
class AdviceCommand(Command):
   def run(self, line):
      advice.give_advice()

advice_command = AdviceCommand('advice', help='Provides advice on next steps and research based on current state')



# console
class ConsoleCommand(Command):
   def run(self, line):
      ishellCompleter = readline.get_completer()
      embed()
      readline.set_completer(ishellCompleter)


console = ConsoleCommand('console', help='Opens an interactive prompt', dynamic_args=True)



# export to file
class ExportCommand(Command):
   def run(self, line):
      def _formatOutput(res):
         if isinstance(res, str):
            return res
         else:
             try:
                 return "\n".join(_formatOutput(r) for r in res)
             except TypeError:
                 return str(res)

      ishellCompleter = readline.get_completer()
      readline.set_completer_delims(' \t\n;')
      readline.parse_and_bind("tab: complete")
      readline.set_completer(completer.complete)

      filePath =  raw_input("Please specify a path to the output file: ").strip()

      readline.set_completer(ishellCompleter)
      if os.path.isfile(filePath):
         confirm = raw_input("File already exists and will be overwritten, confirm? [y/N] ")
         if confirm is "" or confirm[0] not in ("y", "Y"):
            print "Canceled."
            return

      with open(filePath, "w+") as handle:
        handle.write(_formatOutput(feathermodules.results))

export = ExportCommand('export', help='Export current results to file', dynamic_args=True)


# use
class UseCommand(Command):
   def args(self):
      return feathermodules.module_list.keys()
   def run(self, line):
      if line.split()[-1] not in feathermodules.module_list.keys():
         print 'Invalid module selection. Please try again.'
      else:
         feathermodules.selected_attack = feathermodules.module_list[ line.split()[-1] ]
         feathermodules.selected_attack_name = line.split()[-1]
         feathermodules.current_options = feathermodules.selected_attack['options']
    

use = UseCommand('use', help='Select the module to use', dynamic_args=True)

# analyze
class AnalyzeCommand(Command):
   def run(self, line):
      if len(feathermodules.samples) == 0:
         print 'No loaded samples. Please use the \'import\' command.'
         return False
      print '[+] Analyzing samples...'
      feathermodules.analysis_results = ca.analyze_ciphertext(feathermodules.samples, verbose=True)
      if feathermodules.analysis_results['decoded_ciphertexts'] != feathermodules.samples:
         decode = raw_input('[+] Analysis suggests encoded samples. Decode before continuing (Y/n)? ')
         if decode.lower() not in ('n','no','nope','nah','no thank you'):
            feathermodules.samples = feathermodules.analysis_results['decoded_ciphertexts']
      print ''
      print '[+] Suggested modules:'
      for attack in feathermodules.module_list.keys():
         if len(set(feathermodules.module_list[attack]['keywords']) & set(feathermodules.analysis_results['keywords'])) > 0:
            print '   {0:<20} - {1:<57}'.format(attack, feathermodules.module_list[attack]['description'])
   
analyze = AnalyzeCommand('analyze', help='Analyze/decode samples', dynamic_args=True)


# autopwn
class AutopwnCommand(Command):
   def run(self, line):
      if len(feathermodules.samples) == 0:
         print 'No loaded samples. Please use the \'import\' command.'
         return False
      print '[+] Analyzing samples...'
      feathermodules.analysis_results = ca.analyze_ciphertext(feathermodules.samples, verbose=True)
      if feathermodules.analysis_results['decoded_ciphertexts'] != feathermodules.samples:
         feathermodules.samples = feathermodules.analysis_results['decoded_ciphertexts']
      for attack in feathermodules.module_list.keys():
         if len(set(feathermodules.module_list[attack]['keywords']) & set(feathermodules.analysis_results['keywords'])) > 0:
            print 'Running module: %s' % attack
            feathermodules.current_options = feathermodules.module_list[attack]['options']
            if debug:
               print feathermodules.module_list[attack]['attack_function'](feathermodules.samples)
            else:
               try:
                  print feathermodules.module_list[attack]['attack_function'](feathermodules.samples)
               except:
                  print '[*] Module execution failed, please report this issue at https://github.com/nccgroup/featherduster/issues'
   
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
      print '-' * 60
      for sample in feathermodules.samples:
         print repr(sample)
      print '-' * 60

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
      elif feathermodules.selected_attack_name not in feathermodules.module_list.keys():
         print 'Invalid module selection. Please use the \'use\' command.'
         return False
      if debug:
         feathermodules.results = feathermodules.selected_attack['attack_function'](feathermodules.samples)
      else:
         try:
            feathermodules.results = feathermodules.selected_attack['attack_function'](feathermodules.samples)
         except:
            print '[*] Module execution failed, please report this issue at https://github.com/nccgroup/featherduster/issues'
         

run = RunCommand('run', help='Run the currently selected module')


# options
class OptionsCommand(Command):
   def run(self, line):
      if feathermodules.selected_attack_name not in feathermodules.module_list.keys():
         print 'Please select a valid module first.'
         return False
      else:
         print ''
         print '{0:^60}'.format('Currently selected module: ' + feathermodules.selected_attack_name)
         print '-' * 60
         if len(feathermodules.selected_attack['options'].items()) == 0:
            print 'No options to configure.'
         else:
            for option, default in feathermodules.selected_attack['options'].items():
               try:
                  print '{0:<20}{1:>40}'.format(option, feathermodules.current_options[option])
               except:
                  print '{0:<20}{1:>40}'.format(option, default)


# set
class SetCommand(Command):
   def run(self, line):
      line_split = line.split()
      # set option_name value
      if not (len(line_split) == 2 and '=' in line_split[1]):
         print 'Usage: set <option>=<value>'
         return False
      option = line_split[1].split('=')[0]
      first_eq = line_split[1].find('=') 
      value = line_split[1][first_eq+1:]
      feathermodules.current_options[option] = value
   def args(self):
      return feathermodules.selected_attack['options'].keys()


# unset
class UnsetCommand(Command):
   def run(self, line):
      line_split = line.split()
      # unset option_name
      if len(line_split) != 2:
         print 'Usage: unset <option>'
         return False
      option = line_split[1]
      try:
         feathermodules.current_options[option] = feathermodules.selected_attack['options'][option]
      except KeyError:
         print '[*] That option doesn\'t exist, sorry!'
      except AttributeError:
         print '[*] Please select an attack first!'
   def args(self):
      return feathermodules.selected_attack['options'].keys()

# results
class ResultsCommand(Command):
   def run(self, line):
      if not feathermodules.results:
         print 'Last module failed to produce results.'
      elif feathermodules.results == True:
         print 'Last module succeeded, but did not return results.'
      else:
         print 'Last results (long values may be truncated):'
         print '-'*80
         for i in range(len(feathermodules.results)):
            print '{0:d}: {1:60s}'.format(i, repr(feathermodules.results[i]))
      

set_command = SetCommand('set', help='Set an option (i.e., "set num_answers=3"', dynamic_args=True)
unset = UnsetCommand('unset', help='Revert an option to its default value', dynamic_args=True)
options = OptionsCommand('options', help='Show the current option values', dynamic_args=True)
results = ResultsCommand('results', help='Show the results from the last module run')


# Build the console
fd_console = Console(prompt='\nFeatherDuster', prompt_delim='>')

fd_console.addChild(import_sample)
fd_console.addChild(console)
fd_console.addChild(export)
fd_console.addChild(use)
fd_console.addChild(analyze)
fd_console.addChild(autopwn)
fd_console.addChild(search)
fd_console.addChild(samples)
fd_console.addChild(modules)
fd_console.addChild(run)
fd_console.addChild(options)
fd_console.addChild(set_command)
fd_console.addChild(unset)
fd_console.addChild(results)
fd_console.addChild(advice_command)


#--------
# Main menu
#

debug = False

for filename in sys.argv[1:]:
   if filename in ['-h', '--help']:
      print 'Usage: python featherduster.py [ciphertext file 1] ... [ciphertext file n]'
      exit()
   if filename in ['-d', '--debug']:
      debug = True
      print 'Debug mode enabled.'
   try:
      sample_fh = open(filename,'r')
      feathermodules.samples.append(sample_fh.read())
      sample_fh.close()
   except:
      continue

print """Welcome to FeatherDuster!

To get started, use 'import' to load samples.
Then, use 'analyze' to analyze/decode samples and get attack recommendations.
Next, run the 'use' command to select an attack module.
Finally, use 'run' to run the attack and see its output.

For a command reference, press Enter on a blank line.
"""

fd_console.loop()

print '\nThank you for using FeatherDuster!'

def main():
   # blank function so I don't have to restructure this whole file to address an annoying error 
   return 0
