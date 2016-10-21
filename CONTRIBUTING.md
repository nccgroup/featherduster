# Contributing
If you'd like to contribute to FeatherDuster or Cryptanalib, you can do so in a few ways:

* Submitting bug reports and enhancement requests through github issues
* Submitting pull requests to resolve issues
* Contributing attack or helper functions to Cryptanalib
* Contributing FeatherModules

The official page for FeatherDuster and Cryptanalib can be found at https://github.com/nccgroup/featherduster.

# Writing FeatherModules
If you want to write a FeatherModule, the format is relatively simple. A FeatherModule requires:

1. A main function which operates on a list of samples
2. Metadata
   * A reference to the main function
   * A module name
   * The module's category
   * Keywords for analysis results
   * Options, if any, with default values in the form of strings
   
Module main functions should return a list of strings if successful, `False` if unsuccessful,
or `True` if successful with no output.

An example module can be found under `examples/example_feathermodule.py`.

## Custom non-trunk modules

Custom modules can be placed in the `feathermodules/custom` section, where they will be automatically recognized and loaded at runtime. As such, modules that do not meet the contribution requirements listed below can be developed and released as third-party modules and can be used independently of their acceptance into or rejection from the FeatherDuster trunk.

## Analysis results keywords

* `ecb` - Use of ECB mode
* `cbc_fixed_iv` - Use of CBC mode with a fixed key/IV
* `block` - Use of a block cipher
* `md_hashes` - Message Digest family hashes
* `sha1_hashes` - SHA1 hashes
* `sha2_hashes` - SHA2 hashes
* `individually_low_entropy` - Samples pass entropy tests when analyzed individually
* `collectively_low_entropy` - Samples pass entropy tests when analyzed collectively
* `key_reuse` - Samples show signs of key reuse
* `rsa_key` - An RSA key was found in the samples
* `rsa_n_reuse` - Two or more RSA keys were found to have the same modulus
* `rsa_private_key` - An RSA private key was found in the samples
* `rsa_small_n` - An RSA key with a small modulus was found in the samples

# Code structure

* Cryptanalysis library is in `cryptanalib/`
  * Primitives like GCD and CRT in `cryptanalib/helpers.py`
  * Classical/silly crypto solvers in `cryptanalib/classical.py`
  * Modern crypto solvers in `cryptanalib/modern.py`
  * Frequency distribution data is in `cryptanalib/frequency.py`
* FeatherDuster UI is at `featherduster.py`
* FeatherModules are at `feathermodules/`
  * Classical cipher modules at `feathermodules/classical/`
  * Block cipher modules at `feathermodules/block/`
  * Stream cipher modules at `feathermodules/stream/`
  * Hash function modules at `feathermodules/hash/`
  * Asymmetric cipher modules at `feathermodules/pubkey/`
  * Auxiliary modules at `feathermodules/auxiliary/`
  * Custom drop-in directory at `feathermodules/custom/` (don't put things here please)
* Example challenges / scripts / modules at `examples`
* Unit tests at `tests`
* Utilities at `util`

# Contribution requirements
There are a few rules for contributing:

* Code must be your own, or must be released under a license which allows its use in other projects.
* The license on the code must be compatible with the BSD license used by FeatherDuster/Cryptanalib.
* No additional dependencies may be introduced.
* Code must be OS-independent.
* Code must pass unit tests. Execute `python -c 'from tests import *'` in the `featherduster` directory to execute all unit tests.


