import cryptanalib as ca
import feathermodules

def base_n_solve(samples):
   result = ''
   arguments = check_arguments(dict(feathermodules.current_options))
   if arguments == False:
      return '[*] num_answers option must be an integer between 1-35'

   for sample in samples:
      candidate_list = []
      for base in range(2,36+1): # numbers 2-36
         try:
            candidate_list.append(ca.long_to_string(long(sample,base)))
         except:
            continue
      print 'Best answers for sample: {0}\n'.format(sample[:36])
      print '-'*80
      results = sorted(candidate_list[:arguments['num_answers']],key=ca.detect_plaintext)
      print '\n'.join([repr(x) for x in results])
   
   return results

      

def check_arguments(options):
   try:
      options['num_answers'] = int(options['num_answers'])
   except:
      return False

   if not 2 <= options['num_answers'] <= 35:
      return False
   else:
      return options


feathermodules.module_list['base_n_solver'] = {
   'attack_function':base_n_solve,
   'type':'auxiliary',
   'keywords':['classical', 'individually_low_entropy'],
   'description':'A solver for silly base-N encoding obfuscation.',
   'options':{
      'num_answers': '3'
   }
}

