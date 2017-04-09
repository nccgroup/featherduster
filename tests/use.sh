echo 'Testing use command...'
python ./featherduster/featherduster.py <<EOF
use thisisnotarealmodule
use alpha_shift
exit
EOF
