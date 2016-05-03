import sys
import string
import cryptanalib as ca

source = sys.argv[1]
#charset = list(sys.argv[2])
charset = [chr(x) for x in xrange(256)]

source_file = open(source,'r')
source_text = source_file.read()
source_file.close()

#generate character frequency

''' disable digraphs for no-digraph tables
digraphs = []
for char1 in charset:
   for char2 in charset:
      digraphs.append(char1+char2)

charset.extend(digraphs)
'''

char_freq = ca.generate_frequency_table(source_text, charset)

print "frequency_tables['"+sys.argv[3]+"']="+str(char_freq)
