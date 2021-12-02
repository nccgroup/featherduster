import cryptanalib as ca

print 'Testing computation of batch gcd ...'

items = [22499, 21037, 5989, 14863, 4757, 16463, 11639, 11773, 9313, 6313]
correct_result = [1, 193, 113, 1, 67, 1, 113, 193, 67, 1]

if ca.batch_gcd(items) != correct_result:
   raise Exception('Batch GCD is broken.')
