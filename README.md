## SHA256
A size tunable C language implementation of SHA-256.

SHA-256 is a member of the [Secure Hash Algorithm 2](https://en.wikipedia.org/wiki/SHA-2) generating a 256 bit digest.

This implementation was created to provide size tunable code to fit in a memory constrained 32 bit microcontroller.
If your compiler does not implement "unsigned int" as 32 bits, change "unsigned int" in sha256.c @ typedef unsigned int sha256_bt; to, perhaps, "unsigned long".

Included is an example driver program, main.c, that reads standard input till end-of-file and writes on standard output a hex representation of the hash.

Also included is a driver program, shaby.c, to use NIST [test vectors|https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip] to validate the implementation.
Download the ZIP file and expand it in the test directory.
Then type "make check" to validate the SHA256 vectors.
