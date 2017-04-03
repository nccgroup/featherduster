echo 'Testing search command...'
python ./featherduster.py <<EOF
search alpha
search
search thisshouldneverreturnresultsmostlikely
exit
EOF
