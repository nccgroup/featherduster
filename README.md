#FeatherDuster
Featherduster is a tool written by Daniel "unicornfurnace" Crowley of NCC Group for breaking crypto which tries to make the process of identifying and exploiting weak cryptosystems as easy as possible.

This is a beta release of FeatherDuster. Things may be broken.

If you find a bug, please file an issue. Pull requests are welcome and encouraged.

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


#Dependencies
~~~
Python 2.x
GMPy
PyCrypto
~~~

#Installation notes
If you're having trouble installing PyCrypto on an Ubuntu variant, you may not have gcc installed. It's possible to install PyCrypto through apt with `apt-get install python-crypto`.
