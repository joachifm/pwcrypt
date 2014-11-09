{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

{-$todo
- On-disk format: ciphertext + parameters to re-construct key
- Allow user to specify iteration count, guessing takes a while ...
- Use SecureMem for the passphrase
-}

{-$algo

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
-}

import System.CPUTime (getCPUTime)
import Control.Exception (evaluate)

import qualified Crypto.Cipher.AES as AES
import qualified Crypto.PBKDF.ByteString as PBKDF

import qualified Data.ByteString    as SB
import qualified Data.ByteString.Lazy as LB
import qualified Data.Text          as T
import qualified Data.Text.Encoding as T

------------------------------------------------------------------------
-- Random.

-- | Read @n@ octets of random bytes from @/dev/urandom@.
urandom :: Int -> IO SB.ByteString
urandom nbytes = (LB.toStrict . LB.take n') `fmap` LB.readFile "/dev/urandom"
  where n' = fromIntegral nbytes

------------------------------------------------------------------------
-- Key derivation.

-- | Encryption key size, in octets.
kKEYSIZE :: Int
kKEYSIZE = 16 -- 128 bits

{-|
Derive encryption key, given a passphrase, a salt, and an iteration count.
-}
deriveKey :: SB.ByteString -> SB.ByteString -> Int -> SB.ByteString
deriveKey pass salt iter = PBKDF.sha512PBKDF2 pass salt iter kKEYSIZE

{-|
Derive new encryption key from a passphrase, using a randomly generated
salt and a an automatically computed iteration count.

Return the encryption key, the salt, and the iteration count.
-}
deriveKeyIO :: SB.ByteString -> IO (SB.ByteString, SB.ByteString, Int)
deriveKeyIO pass = do
  iter <- guessIterCount
  salt <- urandom kKEYSIZE
  return (deriveKey pass salt iter, salt, iter)

{-|
Find the PBKDF2 iteration count necessary to ensure some lower time bound
on the current hardware.
-}
guessIterCount :: IO Int
guessIterCount = do
  let
    loop !count = do
      t0 <- getCPUTime
      _  <- evaluate (deriveKey "PASS" "SALT" count)
      t1 <- getCPUTime
      if (fromIntegral (t1 - t0) * 1e-12) >= 0.1 -- of a second
         then return count
         else loop (count + 1000)
  loop 2000

------------------------------------------------------------------------
-- Encryption.

{-|
Passphrase protected encryption.

Takes a passphrase and a plaintext, and returns the ciphertext along with
the salt and iteration count used to derive the encryption key.
-}
encrypt :: T.Text -> SB.ByteString -> IO (SB.ByteString, SB.ByteString, Int)
encrypt pass plain = do
  (key, salt, iter) <- deriveKeyIO (T.encodeUtf8 pass)
  let ctx = AES.initAES key
      enc = AES.encryptCTR ctx kNONCE plain
  return (enc, salt, iter)

{-|
Decrypt ciphertext created with 'encrypt'.
-}
decrypt :: T.Text -> SB.ByteString -> Int -> SB.ByteString -> SB.ByteString
decrypt pass salt iter enc =
  let key = deriveKey (T.encodeUtf8 pass) salt iter
      ctx = AES.initAES key
  in AES.decryptCTR ctx kNONCE enc

-- The IV is constant, but the key is random, ensuring
-- unique @(IV, KEY)@.
kNONCE :: SB.ByteString
kNONCE = SB.replicate 16 0

------------------------------------------------------------------------
-- Command-line interface.

main :: IO ()
main = do
  x@(enc, salt, iter) <- encrypt "Muh Passphrase" "Muh Sekret"
  print $ (decrypt "Muh Passphrase" salt iter enc == "Muh Sekret")
  print x
