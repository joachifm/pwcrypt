The following algorithm is based on the scrypt enc utility.

The key derivation inputs are

- A user-supplied passphrase
- A salt
- The iteration count

The derivation algorithm is

- PBKDF2(SHA512, Pass, Salt, c, 16 octets)

The encryption inputs are

- A user-supplied passhprase
- The secret

The encryption algorithm is

1. Derive key from user-supplied passphrase
2. Encrypt the secret with AES in CTR mode using the derived key and
   a constant IV (all KEY/IV pairs are unique because we're using a
   random salt)
