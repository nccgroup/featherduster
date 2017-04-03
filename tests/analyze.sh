echo 'Testing FeatherDuster analyze command...'
python ./featherduster.py <<EOF
import manualentry
12345678
n
analyze
exit
EOF

