import feathermodules
import pydoc

advice_text = {"ecb":
"""
=== ECB MODE ===
Analysis identified that two or more blocks in one of the samples matched. This is incredibly unlikely unless Electronic Code Book mode (ECB) is in use. ECB has a number of known vulnerabilities and is considered dangerous to use.

ECB reveals patterns about the plaintext on a blockwise basis. If two blocks of plaintext are identical, their ciphertext blocks will be identical. Depending on the type of data and the block size, the exposure may be very significant. For a visual illustration of the information leakage from ECB, search for "ECB penguin". If there are only a small number of possible values that can be encrypted under a given system, it may be plausible to build a dictionary of blocks and use them to decrypt encrypted data through inference.

If a system accepts data from you, appends secret data to it, encrypts the combined data, and returns the encrypted version to you, it is possible to obtain the appended secret data byte-by-byte. This can be done using the ecb_cpa_decrypt() function from cryptanalib. For a technical description of how this attack works, visit http://cryptopals.com/sets/2/challenges/12.

Since the meaning of any given block in an ECB ciphertext is independent of its position, it is possible to duplicate, rearrange, or remove blocks in a ciphertext, even between messages encrypted using the same key. Burp Suite's Intruder tool includes an attack method for performing blind ECB block shuffling attacks.
""",

"only_one_sample":
"""
=== ONLY ONE SAMPLE PROVIDED ===
Only one sample was provided. The more samples to analyze, the better chance that analysis will produce accurate results. If possible, gather more samples and re-run analysis.
""",

"small_samples":
"""
=== TOTAL SIZE OF SAMPLE SET IS SMALL ===
The total size of the provided samples is small. With more data to analyze, better results can be produced. If possible, gather more samples and re-run analysis.
""",

"cbc_fixed_iv":
"""
=== BLOCK CIPHER IN CBC MODE WITH FIXED IV ===
Some messages were found to have identical blocks. This may be because a sample was accidentally imported twice. If not, this could indicate either Electronic Code Book mode (ECB) or, if there are identical prefixes, Chained Block Cipher mode (CBC) with a fixed Initialization Vector (IV). CBC with a fixed IV suffers from similar problems to ECB, in that some information about the plaintext is leaked through patterns in the ciphertext. If two messages begin with the same data and that identical data is long enough to fill at least one block, their encrypted versions will have identical blocks at the beginning up to the length of the identical prefixes, as long as the data fills complete blocks.

If there is a system that accepts input from you, appends data to it, encrypts the combined data, and provides you the encrypted data, it is possible to learn the value of the encrypted data.
""",

"blocksize_8":
"""
=== 64 BIT BLOCK CIPHER ===
The length of the imported samples indicate that a block cipher may be in use, as all the lengths of the samples are a multiple of eight bytes in length, one common block size. Some common eight-byte block ciphers include DES, 3DES, and Blowfish, although statistical analysis cannot distinguish between them as of this writing.

Block ciphers with a 64-bit (8-byte) block size suffer from the SWEET32 vulnerability, in which large volumes of data encrypted under the same key can reveal  patterns between different parts of the message using known or chosen plaintext attacks. More information about SWEET32 can be found at https://sweet32.info.
""",

"blocksize_16":
"""
=== 128 BIT BLOCK CIPHER ===
The length of the imported samples indicate that a block cipher may be in use, as all the lengths of the samples are a multiple of sixteen bytes in length, one common block size. Some common sixteen-byte block ciphers include AES and Twofish, although statistical analysis cannot distinguish between them as of this writing.
""",

"md_hashes":
"""
=== MESSAGE DIGEST HASH ===
All unencoded samples were sixteen bytes in length. This might indicate that all samples were the result of a hash function with a sixteen-byte output. Notable hash functions whose outputs are of this length are the Message Digest hash family, which includes the functions MD2, MD4, and MD5. These hash functions are all known to be vulnerable to length extension attacks.

MD5 is a very commonly used hash function and has known issues. It is possible to create two distinct pieces of data which produce identical MD5 hashes. This can be used to launch meaningful attacks due to the Merkle-Damgard construction used by MD5. If you have two MD5-colliding pieces of data m1 and m2, you can append them to some piece of data and they will still produce identical MD5 hashes:

MD5('foobar' || m1) == MD5('foobar' || m2)

It is also possible to append identical data to both m1 and m2 and they will still produce identical MD5 hashes.
""",

"sha1_hashes":
"""
=== SHA1 HASH ===
The length of the samples indicates that they may be the result of the SHA-1 hash function, or, less likely, the RIPEMD-160 hash function.

SHA-1 is known to suffer from collision issues, but as of 2017 the computation needed to produce SHA-1 colliding values is outside the capabilities of all but the most well-resourced attackers. Google has published two PDF documents that produce the same SHA-1 hash but show different content as a proof-of-concept.

It is possible to append the colliding data produced and published by Google to a piece of data and produce different files that produce the same SHA-1 hash due to its Merkle-Damgard construction.
""",

"sha2_hashes":
"""
=== SHA2 HASH ===
The length of the samples indicates that they may be produced by one variant of the SHA-2 hash function family.
""",

"not_individually_random":
"""
=== INDIVIDUAL SAMPLES FAILED RANDOMNESS TESTS ===
One or more samples failed statistical tests designed to test the quality of pseudo-random number generators (PRNGs) when analyzed individually.
""",

"not_collectively_random":
"""
=== CONCATENATED SAMPLE SET FAILED RANDOMNESS TESTS ===
The samples failed statistical tests designed to test the quality of pseudo-random number generators (PRNGs) when concatenated and analyzed.
""",

"not_random":
"""
If the samples being analyzed are the output of a PRNG, this may indicate that the PRNG is weak.

Modern ciphers are designed to produce output that's indistinguishable from random data, so if the samples provided are ciphertexts, this may indicate that the data is encrypted poorly.

This may be a false positive if samples are small, or if the samples include more than just ciphertext or random data, such as with a sample like '{"ciphertext":"<ciphertext here>"}'.
""",

"decoded_ciphertexts":
"""
=== ENCODING DETECTED ===
The samples were identified as being encoded. After being decoded, they may be human-readable. If you'd like to inspect them, you can do so using the `samples` command.
""",

"key_reuse":
"""
=== POSSIBLE KEY REUSE ===
Analysis indicates that there are some potential relationships between different parts of the provided sample data. This may indicate key reuse, or a deterministic encryption algorithm.

If the data is produced by a stream cipher, key reuse is catastrophic and can result in the ability to decrypt data without any knowledge or capabilities other than access to encrypted messages.
""",

"rsa_private_key":
"""
=== PRIVATE KEY DETECTED ===
An RSA private key was discovered among the samples provided. If no private keys should be among the samples provided, this may be an issue.
""",

"rsa_small_n":
"""
=== SMALL RSA PUBLIC KEY ===
One of the RSA keys was found to have a small public key length. If the public key is too small, it may be possible to recover the private key by attempting brute-force factorization of the modulus, such as with a number factoring utility like YAFU, or by looking up the modulus on https://factordb.com.
""",

"is_transposition_only":
"""
=== TRANSPOSITION-ONLY CIPHER ===
The ciphertexts match the expected frequency distribution of plaintext. It may be that the ciphertext is encrypted with a transposition-only cipher, meaning that all the bytes of the data are intact, but their order is changed. Transposition-only ciphers are not used in practice in modern cryptography, so these samples may indicate that a classical cipher is in use.
""",

"is_polybius":
"""
=== POLYBIUS CIPHER === 
The ciphertext appears to be the result of a polybius square cipher. This is a classical cipher and is not considered secure for modern use.
""",

"is_all_alpha":
"""
=== ALPHABET-ONLY CIPHER ===
The ciphertext is made up entirely of letters. This might be an encoding scheme that FeatherDuster is not capable of decoding, such as a custom encoding scheme, or it may be a classical cipher that is only capable of processing letters.
""",

"no_samples":
"""
=== NO SAMPLES PROVIDED ===
No samples appear to be imported. To import a sample, you can use the 'import' command, or provide filenames of files containing a single ciphertext each as positional arguments when launching featherduster, like so:

featherduster encrypted1.bin encrypted2.bin

For more help using the 'import' command, try 'help import'.
""",

"gathering_samples":
"""
It may be possible to provide input to be encrypted. For instance, if passwords for a web application are being stored in a database and you have gained access to the database, you can change your password to various values and retrieve each value from the database.

Known in the crypto community as a "chosen plaintext" scenario, access to a system that will encrypt data of your choice, or "encryption oracle", not only opens up lots of possibilities for attacks, but also allows for more accurate fingerprinting of the method used to transform the data.

The following is a list of inputs that may be useful in determining what the algorithm is:

(nothing)
A * 1
A * 8
A * 16
A * 32
A * 32 (again, to check determinism)
B * 32 + A * 32
ABCDEFGHIJKLMNOPQRSTUVWXYZ
""",

"analysis_guide":
"""
=== SAMPLES HAVE NOT BEEN ANALYZED ===
Analysis has not yet been performed. Try using the 'analyze' command.
""",

"merkle_damgard":
"""
Based on analysis, the samples might be hashes produced by a hash function based on a Merkle-Damgard construction. This is a way of building hash functions based on lossy compression functions. An initial hard-coded state is combined with chunks of the input data one at a time, changing the state with each chunk. Once all the input has been processed, the state is returned as the output of the hash function.

The Merkle-Damgard construction is vulnerable to what's known as a "hash length extension" attack, where an attacker in possession of a hash for some value m can produce a hash for m || padding || x, where padding is the padding defined by the hash function to make equal sized blocks for processing with the compression function when not enough input data exists, and x is a value of the attacker's choosing. This can be used to subvert a common, but naive, digital signature algorithm where data to be signed is appended to a secret value and hashed like so: HASH(secret || input). A public example of this is the Flickr signature forgery vulnerability.
"""
}

def give_advice():
   advice = ''
   if feathermodules.samples == []:
      advice += advice_text['no_samples']
      advice += advice_text['gathering_samples']
      print advice
      return

   give_sample_advice = False
   if len(feathermodules.samples) == 1:
      advice += advice_text['only_one_sample']
      give_sample_advice = True
   if len(''.join(feathermodules.samples)) <= 100:
      advice += advice_text['small_samples']
      give_sample_advice = True
   if give_sample_advice == True:
      advice += advice_text['gathering_samples']

   if feathermodules.analysis_results == False:
      advice += advice_text['analysis_guide']
      print advice
      return
   
   if feathermodules.analysis_results['decoded_ciphertexts']:
      advice += advice_text['decoded_ciphertexts']

   merkle_damgard = False
   if feathermodules.analysis_results['md_hashes']:
      advice += advice_text['md_hashes']
      merkle_damgard = True
   if feathermodules.analysis_results['sha1_hashes']:
      advice += advice_text['sha1_hashes']
      merkle_damgard = True
   if feathermodules.analysis_results['sha2_hashes']:
      advice += advice_text['sha2_hashes']
      merkle_damgard = True
   if merkle_damgard == True:
      advice += advice_text['merkle_damgard']

   if feathermodules.analysis_results['blocksize'] != False:
      if feathermodules.analysis_results['blocksize'] == 8:
         advice += advice_text['blocksize_8']
      if feathermodules.analysis_results['blocksize'] == 16:
         advice += advice_text['blocksize_16']
      if feathermodules.analysis_results['ecb']:
         advice += advice_text['ecb']
      if feathermodules.analysis_results['cbc_fixed_iv']:
         advice += advice_text['cbc_fixed_iv']
         
   if feathermodules.analysis_results['individually_random'] == False or feathermodules.analysis_results['collectively_random'] == False:
      advice += advice_text['not_random']
      if feathermodules.analysis_results['individually_random'] == False:
         advice += advice_text['not_individually_random']
      else: 
         advice += advice_text['not_collectively_random']

   if feathermodules.analysis_results['rsa_key']:
      advice += advice_text['rsa_key']
      if feathermodules.analysis_results['rsa_private_key']:
         advice += advice_text['rsa_private_key']
      if feathermodules.analysis_results['rsa_small_n']:
         advice += advice_text['rsa_small_n']
   
   if feathermodules.analysis_results['is_transposition_only']:
      advice += advice_text['is_transposition_only']
   if feathermodules.analysis_results['is_polybius']:
      advice += advice_text['is_polybius']
   if feathermodules.analysis_results['is_all_alpha']:
      advice += advice_text['is_all_alpha']

   pydoc.pager(advice)
