#FeatherDuster (and Cryptanalib)
FeatherDuster is a tool written by Daniel "unicornfurnace" Crowley of NCC Group for breaking crypto which tries to make the process of identifying and exploiting weak cryptosystems as easy as possible. Cryptanalib is the moving parts behind FeatherDuster, and can be used independently of FeatherDuster.

This is a beta release of FeatherDuster. Things may be broken.

If you find a bug, please file an issue. Pull requests are welcome and encouraged.

#Installation
~~~
git clone https://github.com/nccgroup/featherduster.git
cd featherduster
python setup.py install
~~~

#Usage
`python featherduster.py [ciphertext file 1] ... [ciphertext file n]`

When importing samples through positional arguments, each file will be consumed and treated as its own ciphertext, regardless of the format of the files. FeatherDuster has the ability to automatically recognize and decode common encodings, so it's okay if these files contain encoded samples.

Invoking FeatherDuster without positional arguments will allow for alternate methods of ciphertext import, specifically the ability to import a file with newline-separated samples where each line will be treated as a distinct sample, like so:

~~~
68657920636f6f6c
796f752072656164
74686520726561646d65
~~~

and the ability to specify a single ciphertext in FeatherDuster through command-line input. Since this input will terminate on a newline, it is recommended to use some form of encoding in case the sample contains a newline.

#The Cryptanalib analysis engine

The analysis engine in Cryptanalib, used by FeatherDuster, can automatically detect encodings and decode samples. The engine assumes that all samples are generated with the same process (for instance, `base64encode(aes_encrypt(datum))`), but can handle mixed samples to some degree. Currently, Cryptanalib can detect and decode the following encoding schemes:

~~~
Vanilla Base64
ASCII hex-encoding
Zlib compression
~~~

Cryptanalib's analysis engine can detect a number of properties in the analysis phase, too:

~~~
Low entropy ciphertext *(Useful for detecting homebrew ciphers)*
Block cipher usage vs Stream cipher usage
ECB mode
CBC mode with fixed IV
Hashes *(engine will note that length extension attacks may apply with Merkle-Daamgard based hash algos)*
OpenSSL formatted ciphertext
Stream cipher key reuse
RSA keys with private components
Insufficiently large RSA moduli
RSA modulus reuse
Transposition-only cipher
~~~

#Dependencies
~~~
Python 2.x
GMPy
PyCrypto
~~~

#Installation notes
If you're having trouble installing PyCrypto on an Ubuntu variant, you may not have gcc installed. It's possible to install PyCrypto through apt with `apt-get install python-crypto`.
