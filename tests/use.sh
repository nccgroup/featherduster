echo 'Testing use command...'
python ./featherduster/featherduster.py --debug <<EOF
use thisisnotarealmodule
use alpha_shift
exit
EOF
