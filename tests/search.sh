echo 'Testing search command...'
python ./featherduster/featherduster.py <<EOF
search alpha
search
search thisshouldneverreturnresultsmostlikely
exit
EOF
