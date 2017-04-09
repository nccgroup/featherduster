echo 'Testing multi-ciphertext file import...'
python ./featherduster/featherduster.py << EOF | egrep "^'c7629149911e324e0322913e2e35c3b0fcea5180608a3f74cef73a010a6f71f49f346442f524a06578bfdfece04af86e8b8ad38bdb1cac4d6602fa4f2e'\$"
import multifile
examples/manytimepad.ciphertexts
samples
EOF
