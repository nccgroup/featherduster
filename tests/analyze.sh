echo 'Testing FeatherDuster analyze command...'
python ./featherduster/featherduster.py <<EOF
import manualentry
12345678
n
analyze
exit
EOF

