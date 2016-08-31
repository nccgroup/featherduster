import cryptanalib as ca

ct = 'XUEGTZFZARLMOWPAQRNUPLQKWPRJABVURBFBAWYEEYPILJRZMPCJAPRXANSGZZZAPNTFOJLRIBNCLBGOWGABWJRXXVASZCAJEADVDMQGQRTBWKVVLRRETAPZSFWJEKUHIGWFPVPOTUESLTCNEOEUDIYHIETJDALYXRMPYTLYAVTDSMQGPCHBMMGYESTFCARBIEAMHWEJWNNEDEVZGUETHMEKMADJNIGKHOYXCQGORTTIPTRZXRRPQBUKGBRSPACURQIORIYVLNBFEQAZLRCJAPRXXRXU'

print 'Testing vigenere solver...'
key = ca.break_vigenere(ct, 11)

print ca.translate_vigenere(ct, key, decrypt=True)
