echo 'Testing options command...'
python ./featherduster/featherduster.py --debug <<EOF
options
use alpha_shift
options
use vigenere
options
exit
EOF
