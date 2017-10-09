echo 'Testing run command...'
python ./featherduster/featherduster.py --debug <<EOF
run
use alpha_shift
run
import manualentry
gdkkn
run
import clear
run
exit
EOF
