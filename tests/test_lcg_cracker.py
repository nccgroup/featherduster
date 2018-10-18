import cryptanalib as ca
import os
from Crypto.Util.number import bytes_to_long

lcg_state = bytes_to_long(os.urandom(4)) % 101020101

def lcg(state):
   next_state = (31337 * state + 1337) % 101020101
   return next_state

states = []

current_state = correct_prev_state = lcg(lcg_state)

for i in range(10):
   current_state = lcg(current_state)
   states.append(current_state)

correct_next_state = lcg(current_state)

print correct_prev_state
print states
print correct_next_state

print 'Testing LCG cracker...'

print '...with known a,c,m...'
assert ca.lcg_next_states(states, 1, a=31337, c=1337, m=101020101)[0] == correct_next_state
print '...with known a,m...'
assert ca.lcg_next_states(states, 1, a=31337, m=101020101)[0] == correct_next_state

print 'Testing previous state recovery...'

print '...with known a,c,m...'
assert ca.lcg_prev_states(states, 1, a=31337, c=1337, m=101020101)[0] == correct_prev_state
print '...with known a,m...'
assert ca.lcg_prev_states(states, 1, a=31337, m=101020101)[0] == correct_prev_state
