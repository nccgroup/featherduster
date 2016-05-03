import cryptanalib as ca
import feathermodules

def detect_hash_format(hashes):
   words = raw_input('Please enter words that might be in the plaintext version of the hashes, comma-separated: ').split(',')
   return ca.detect_hash_format(words,hashes)


feathermodules.module_list['detect_hash_format'] = {
   'attack_function':detect_hash_format,
   'type':'auxiliary',
   'keywords':['md_hashes','sha1_hashes','sha2_hashes'],
   'description':'Try hashing all permutations of provided words with different delimiters to determine how data is put together before hashing.'
}
