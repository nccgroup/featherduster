echo 'Testing samples command...'
python ./featherduster/featherduster.py --debug <<EOF
samples
import manualentry
gdkkn
samples
import clear
samples
exit
EOF
