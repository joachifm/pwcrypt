# About

A simple command-line utility for password-protected
file encryption, akin to the scrypt utility.

# Usage

```sh
pwenc enc foo.txt foo.txt.enc
pwenc dec foo.txt.enc foo.txt
```

# Algorithm

The algorithm is based on the scrypt encryption utility.
Basically, the input is encrypted using a key derived
from a user-supplied passphrase and a random salt.

## The key derivation inputs are

- A user-supplied passphrase
- A salt
- The iteration count

## The key derivation function is

PBKDF2(SHA512, Pass, Salt, c, 16 octets), which
results in a 128 bit key.

## The encryption inputs are

- A user-supplied passhprase
- A random salt
- The secret

## The encryption algorithm is

1. Derive key from user-supplied passphrase and salt
2. Encrypt the secret with AES in CTR mode using the derived key and
   a constant IV
