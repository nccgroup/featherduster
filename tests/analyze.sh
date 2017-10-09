echo 'Testing FeatherDuster analyze command...'
python ./featherduster/featherduster.py --debug <<EOF
import manualentry
12345678
analyze
n
exit
EOF

