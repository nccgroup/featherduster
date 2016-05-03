import cryptanalib as ca
from Crypto import Random

key = Random.new().read(40)

plaintexts = [
'Who da man? I am! I am the man!',
'Who run Barter Town? Master Blaster!',
'Damon brings in tacos from Taco Hut',
'He was an analyst, he brought tacos',
'I am looking for Skyrim employment',
'You might say I\'m looking for Skyrim work',
'Almost as if I\'m seeking a Skyrim trade',
'You could say I want a Skyrim labor agreement',
'I used to be an adventurer like you',
'Until I took an arrow to the knee',
'Okay, the joke is Skyrim job, it\'s funny'
'Can I stop writing out plaintexts now',
'Charles Dickens is a big windbag',
'I can only come up with so much random',
'stuff and then I have to ask for help',
'from Will, who just repeats my words',
'My brain is melting, as is my waaaaaaaaang',
'I really need more sleep than I get',
'Sleep is for the weak, Skub is for the strong',
'Fuck those anti-skub losers, skub is the best'
]

ciphertexts = []

for plaintext in plaintexts:
   ciphertexts.append(ca.sxor(key, plaintext))

print 'Testing many-time pad solver...'
print ca.break_many_time_pad(ciphertexts)
if raw_input('Did this decrypt correctly (yes)?').lower() not in ['y','yes','']:
   raise Exception('Many time pad solver failed.')
