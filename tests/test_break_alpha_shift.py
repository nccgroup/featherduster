import cryptanalib as ca

ct = 'znoy oy se iovnkxzkdz. oz\'y gckyusk gtj cutjkxlar.'
real_pt = 'this is my ciphertext. it\'s awesome and wonderful.'

print 'Testing alphabetic shift solver...'
pt = ca.break_alpha_shift(ct)

if real_pt != pt[0]:
   raise Exception('Failed to break alpha shift.')
