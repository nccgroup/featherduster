import cryptanalib as ca
from Crypto import Random

key = Random.new().read(100)

plaintexts = """I am the very model of a modern Major-General
I've information vegetable, animal, and mineral
I know the kings of England, and I quote the fights historical
From Marathon to Waterloo, in order categorical
I'm very well acquainted, too, with matters mathematical
I understand equations, both the simple and quadratical
About binomial theorem I'm teeming with a lot o' news
With many cheerful facts about the square of the hypotenuse
I'm very good at integral and differential calculus
I know the scientific names of beings animalculous
In short, in matters vegetable, animal, and mineral
I am the very model of a modern Major-General
I know our mythic history, King Arthur's and Sir Caradoc's
I answer hard acrostics, I've a pretty taste for paradox
I quote in elegiacs all the crimes of Heliogabalus
In conics I can floor peculiarities parabolous
I can tell undoubted Raphaels from Gerard Dows and Zoffanies
I know the croaking chorus from The Frogs of Aristophanes!
Then I can hum a fugue of which I've heard the music's din afore
And whistle all the airs from that infernal nonsense Pinafore
Then I can write a washing bill in Babylonic cuneiform
And tell you ev'ry detail of Caractacus's uniform
In short, in matters vegetable, animal, and mineral
I am the very model of a modern Major-General
In fact, when I know what is meant by "mamelon" and "ravelin"
When I can tell at sight a Mauser rifle from a javelin
When such affairs as sorties and surprises I'm more wary at
And when I know precisely what is meant by "commissariat"
When I have learnt what progress has been made in modern gunnery
When I know more of tactics than a novice in a nunnery
In short, when I've a smattering of elemental strategy
You'll say a better Major-General has never sat a gee
For my military knowledge, though I'm plucky and adventury
Has only been brought down to the beginning of the century
But still, in matters vegetable, animal, and mineral
I am the very model of a modern Major-General."""

plaintexts = plaintexts.split('\n')

ciphertexts = []

for plaintext in plaintexts:
   ciphertexts.append(ca.sxor(key, plaintext))

print 'Testing many-time pad solver...'
answers = ca.break_many_time_pad(ciphertexts, verbose=True)

total_bit_length = 0
bits_correct = 0

for (correct_answer, actual_answer) in zip(plaintexts, answers):
   bit_length = len(correct_answer) * 8
   total_bit_length += bit_length
   bits_correct += bit_length - ca.hamming_distance(correct_answer, actual_answer)
         
accuracy = bits_correct / float(total_bit_length) 

if accuracy < .90:
   exit('Many time pad cracker accuracy has reduced below 90% accuracy. Test failed.')
