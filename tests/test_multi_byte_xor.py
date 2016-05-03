import cryptanalib as ca
ct_file = open('testdata/multibyte_decoded.ct','r')
ct = ct_file.read()
ct_file.close()
print ca.break_multi_byte_xor(ct, num_answers=3, verbose=True)[0]

if raw_input('Do you see Vanilla Ice lyrics (yes)?').lower() not in ['y','yes','']:
   raise Exception('Multi byte XOR attack is broken.')
