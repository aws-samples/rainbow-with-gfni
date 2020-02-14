GFNI based Rainbow (IIIc_Classic)
-----------------------------------------------------------------------------

[Rainbow](https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions) is a signature scheme. It is one of the submissions to [NIST’s Post-Quantum Cryptography Standardization project]( https://csrc.nist.gov/projects/post-quantum-cryptography).

This sample code package is an optimized version of Rainbow (IIIc_Classic). It starts from the official [Round-2 Rainbow code package](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-2/submissions/Rainbow-Round2.zip) downloaded at 01/02/2020. The optimizations in this package are achieved through using the following features:
- The x86-64 AVX512 extension
- An [AES256 CTR-DRBG with Vector AES-NI instructions](https://github.com/aws-samples/ctr-drbg-with-vector-aes-ni) implementation
- The x86-64 GF-NI extension (new instructions for GF(2^8) computations)

This package offers an optimized version of Rainbow with AVX512 and Vector AES and GFNI (which are available since Intel(R) 10th generation)

For a detailed description of the optimizations in this package, see: 
- Nir Drucker, Shay Gueron, "Speed up over the Rainbow", IACR ePrint, 2020.

For a detailed description on using the GF-NI instructions, see:
- Drucker, Nir, Shay Gueron, and Vlad Krasnov. 2018. “The Comeback of Reed Solomon Codes.” In 2018 IEEE 25th Symposium on Computer Arithmetic (ARITH), 125–29. [https://doi.org/10.1109/ARITH.2018.8464690](https://doi.org/10.1109/ARITH.2018.8464690).

The code is due to Nir Drucker and Shay Gueron. 

BUILD
-----

To compile:
    make

Additional compilation flags:
 - SPECIAL_PIPELINING   - Enable inline assembler code
 - UNROLL_LOOPS         - Ask the compiler to unroll all loops
 - USE_AES_FIELD        - Work in the AES field (different than the original implementation)
 - ASAN/MSAN/UBSAN/TSAN - Enable the associated clang sanitizer
 - USE_ORIG_TEST        - Use the original main file and NIST RNG that came with the original Rainbow package
 - USE_ORIG_RNG         - Use the RNG of the original Rainbow package. This is require for KAT compariosn. This flag is only relevant when USE_ORIG_TEST=1
 - NO_VAES              - Do not use Vector-AES for the DRBG

Example: 

`make USE_AES_FIELD=1 UNROLL_LOOPS=1`

To clean:

`make clean`

Note: a "clean" is required prior to compilation with modified flags.

To format (`clang-format-9` is required):

`make pretty`

To use clang-tidy (`clang-tidy-9` is required):

`make clang-tidy`

Before committing a code, please test it using
`make pre-commit-test` 
This will run all the sanitizers and also `clang-format` and `clang-tidy`.

Supported compilers
-------------------
Use the following compilers that support the GF-NI and Vector AES extensions
- `clang-9` and above
- `gcc-10` and above

Note that `gcc-8/9` supports these instructions but it has a [bug](https://www.mail-archive.com/gcc-bugs@gcc.gnu.org/msg632510.html).

The package was compiled and tested with clang-9 in 64-bit mode. 
Tests were run on a Linux (Ubuntu 16.04.3 LTS) OS. 
Compilation on other platforms may require some adjustments.

## License
This project is licensed under the Apache-2.0 License.

