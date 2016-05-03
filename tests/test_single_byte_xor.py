import cryptanalib as ca

plaintext = 'I am the very model of a modern major-general'

ciphertext = ca.sxor(plaintext, '\x3f'*len(plaintext))
output = ca.break_single_byte_xor(ciphertext)
print output
if output[0][0] != plaintext:
   raise Exception('Single byte XOR solver is broken')
