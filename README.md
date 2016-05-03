#FeatherDuster
Featherduster is a tool written by Daniel "unicornfurnace" Crowley of NCC Group for breaking crypto which tries to make the process of identifying and exploiting weak cryptosystems as easy as possible.

This is a beta release of FeatherDuster. Things may be broken.

If you find a bug, please file an issue. Pull requests are welcome and encouraged.

#Usage
`python featherduster.py [ciphertext file 1] ... [ciphertext file n]`

#Dependencies
~~~
Python 2.x
GMPy
PyCrypto
~~~

#Installation notes
If you're having trouble installing PyCrypto on an Ubuntu variant, you may not have gcc installed. It's possible to install PyCrypto through apt with `apt-get install python-crypto`.
