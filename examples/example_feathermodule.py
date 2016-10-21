# Character order reverse transposition cipher FeatherModule by Daniel Crowley
#
# This is meant to serve as an example FeatherModule to ease the development process
# for FeatherModule developers.

# We don't need this here, but if we wanted to use cryptanalib functionality we'd uncomment the next line
# import cryptanalib as ca

# We must `import feathermodules` as a means of keeping state across different parts of FD
import feathermodules

# Our main function
def reverse_transposition(samples):
   # Load the current set of options from FD, using dict() so we get a copy
   # rather than manipulating the original dict
   options = dict(feathermodules.current_options)
   results = []
   for sample in samples:
      if options['double'].lower() in ['y', 'yes', 'true', 'sure', 'ok', 'i guess so']:
         # Super efficient double-reverse transposition algorithm implementation
         results.append(sample)
      else:
         results.append(sample[::-1])
   print 'Decrypted results:'
   print '-' * 80
   print '\n'.join(results)
   return results


feathermodules.module_list['reverse_trans'] = {
   # Note that we are using a reference to a function rather than a string here so that we can
   # simply invoke feathermodules.selected_attack['attack_function']
   'attack_function': reverse_transposition,
   'type':'classical',
   'keywords':['transposition'],
   'description':'A module to break the super-secure string reverse transposition cipher or its double-reverse variant.',
   # Yo dawg I herd u liek Python dict objects so I put a Python dict object
   # in your Python dict object so you can index by key while you index by key
   'options': {
      'double': 'no'
   }
}
