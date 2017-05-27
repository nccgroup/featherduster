import cryptanalib as ca
import feathermodules

def many_time_pad_attack(ciphertexts):
   arguments = get_arguments(ciphertexts)
   plaintexts = ca.break_many_time_pad(arguments['ciphertexts'],arguments['plaintext_language'], verbose=True)
   if plaintexts != False:
      print '\n'.join(plaintexts)
   return plaintexts


def get_arguments(ciphertexts):
   arguments = {}
   arguments['ciphertexts'] = ciphertexts
   arguments['plaintext_language'] = ca.frequency.frequency_tables['english'] #TODO: expand to different languages
   return arguments


feathermodules.module_list['many_time_pad'] = {
   'attack_function':many_time_pad_attack,
   'type':'stream',
   'keywords':['key_reuse', 'collectively_low_entropy'],
   'description':'A statistical attack against keystream reuse in various stream ciphers, and the one-time pad.',
   'options':{}
}
