# FeatherDuster (and Cryptanalib)
![FeatherDuster logo ](fd_logo.png)
[![Build Status](https://travis-ci.org/nccgroup/featherduster.svg?branch=master)](https://travis-ci.org/nccgroup/featherduster)

FeatherDuster is a tool written primarily by Daniel "unicornfurnace" Crowley, along with community contributions, for breaking crypto; It tries to make the process of identifying and exploiting weak cryptosystems as easy as possible. Cryptanalib is the moving parts behind FeatherDuster, and can be used independently of FeatherDuster.

Why "FeatherDuster"? There's an in-joke amongst some crypto folk where using crypto poorly, or to solve a problem that crypto isn't meant to solve is called "sprinkling magical crypto fairy dust on it". FeatherDuster is for cleaning up magical crypto fairy dust.

This is a beta release of FeatherDuster. Things may be broken.

If you find a bug, please file an issue. Pull requests are welcome and encouraged.

# FeatherDuster Usage
`python featherduster/featherduster.py [ciphertext file 1] ... [ciphertext file n]`

If you have installed FeatherDuster into your virtual environment, you can simply run it as:
```bash
(featherduster) $ featherduster [ciphertext file 1] ... [ciphertext file n]
```

When importing samples through positional arguments, each file will be consumed and treated as its own ciphertext, regardless of the format of the files. FeatherDuster has the ability to automatically recognize and decode common encodings, so it's okay if these files contain encoded samples.

Once the FeatherDuster console launches, alternate methods of ciphertext import will be available, specifically the ability to import a file with newline-separated samples where each line will be treated as a distinct sample, like so:

~~~
68657920636f6f6c
796f752072656164
74686520726561646d65
~~~

and the ability to specify a single ciphertext in FeatherDuster through command-line input. Since this input will terminate on a newline, it is recommended to use some form of encoding in case the sample contains a newline.

# Cryptanalib Usage
Cryptanalib can be used separately of FeatherDuster to make Python-based crypto attack tools. Documentation for cryptanalib functions can be accessed through the Python `help()` function like so:

~~~
>>> import cryptanalib as ca
>>> dir(ca)    # output edited for a cleaner README file
[ ... 'analyze_ciphertext', 'batch_gcd', 'bb98_padding_oracle', 'break_alpha_shift', 'break_ascii_shift', 'break_columnar_transposition', 'break_generic_shift', 'break_many_time_pad', ... ]
>>> help(ca.bb98_padding_oracle)

Help on function bb98_padding_oracle in module cryptanalib:

bb98_padding_oracle(ciphertext, padding_oracle, exponent, modulus, verbose=False, debug=False)
    Bleichenbacher's RSA-PKCS1-v1_5 padding oracle from CRYPTO '98
    
    Given an RSA-PKCS1-v1.5 padding oracle and a ciphertext,
    decrypt the ciphertext.
    
    ciphertext - The ciphertext to decrypt
    padding_oracle - A function that communicates with the padding oracle.
       The function should take a single parameter as the ciphertext, and
       should return either True for good padding or False for bad padding.
    exponent - The public exponent of the keypair
    modulus - The modulus of the keypair
    verbose - (bool) Whether to show verbose output
    debug - (bool) Show very verbose output
~~~

# The Cryptanalib analysis engine

The analysis engine in Cryptanalib, used by FeatherDuster, can automatically detect encodings and decode samples. The engine assumes that all samples are generated with the same process (for instance, `base64encode(aes_encrypt(datum))`), but can handle mixed samples to some degree. Currently, Cryptanalib can detect and decode the following encoding schemes:

* Vanilla Base64
* ASCII hex-encoding
* Zlib compression
* URL encoding

Cryptanalib's analysis engine can detect a number of properties in the analysis phase, too:

* Low entropy ciphertext (Useful for detecting homebrew ciphers)
* Block cipher usage vs Stream cipher usage
* ECB mode
* CBC mode with fixed IV
* Hash algorithm (engine will note that length extension attacks may apply with Merkle-Daamgard based hash algos)
* OpenSSL formatted ciphertext
* Stream cipher key reuse
* RSA keys with private components
* Insufficiently large RSA moduli
* RSA modulus reuse
* Transposition-only cipher
