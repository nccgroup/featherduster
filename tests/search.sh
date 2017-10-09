echo 'Testing search command...'
python ./featherduster/featherduster.py --debug <<EOF
search alpha
search
search thisshouldneverreturnresultsmostlikely
exit
EOF
