{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto (
    getSalt
  , guessIterCount
  , encrypt
  , decrypt
  , encode
  , decode
  ) where

import System.CPUTime (getCPUTime)
import Control.Exception (evaluate)

import Data.Maybe (fromMaybe)

import qualified Crypto.Cipher.AES       as AES
import qualified Crypto.PBKDF.ByteString as PBKDF

import Data.String (fromString)
import qualified Data.ByteString      as SB
import qualified Data.ByteString.Lazy as LB

import qualified Data.ByteString.Base64 as Base64

------------------------------------------------------------------------
-- Random.

-- | Read @n@ octets of random data from @/dev/urandom@.
urandom :: Int -> IO SB.ByteString
urandom nbytes = (LB.toStrict . LB.take n') `fmap` LB.readFile "/dev/urandom"
  where n' = fromIntegral nbytes

------------------------------------------------------------------------
-- Key derivation.

-- | Hash output size, in octets
kHASHSIZE :: Int
kHASHSIZE = 64

-- | Encryption key size, in octets.
kKEYSIZE :: Int
kKEYSIZE = 16

{-|
Get random salt for key derivation.
-}
getSalt :: IO SB.ByteString
getSalt = urandom kHASHSIZE

{-|
Derive encryption key, given a passphrase, a salt, and an iteration count.
-}
deriveKey :: SB.ByteString -> SB.ByteString -> Int -> SB.ByteString
deriveKey pass salt iter = PBKDF.sha512PBKDF2 pass salt iter kKEYSIZE

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
  loop 1000

------------------------------------------------------------------------
-- Encryption.

kNONCE :: SB.ByteString
kNONCE = SB.replicate 16 0

encrypt :: SB.ByteString
        -> SB.ByteString
        -> Int
        -> SB.ByteString
        -> SB.ByteString
encrypt pass salt iter plain =
  let key = deriveKey pass salt iter
      ctx = AES.initAES key
  in AES.encryptCTR ctx kNONCE plain

decrypt :: SB.ByteString
        -> SB.ByteString
        -> Int
        -> SB.ByteString
        -> SB.ByteString
decrypt pass salt iter ciphr =
  let key = deriveKey pass salt iter
      ctx = AES.initAES key
  in AES.decryptCTR ctx kNONCE ciphr

------------------------------------------------------------------------
-- Encoding

encode :: SB.ByteString -- ^ Salt
       -> Int           -- ^ Iteration count
       -> SB.ByteString -- ^ Ciphertext
       -> (SB.ByteString, Int, SB.ByteString)
encode salt iter enc = (Base64.encode salt, iter, Base64.encode enc)

decode :: (SB.ByteString, Int, SB.ByteString)
       -> Either String (SB.ByteString, Int, SB.ByteString)
decode (salt, iter, enc) =
  case Base64.decode salt of
    Right s -> case Base64.decode enc of
      Right e  -> Right (s, iter, e)
      Left msg -> Left ("Failed to decode the ciphertext: " ++ msg)
    Left msg -> Left ("Failed to decode the salt: " ++ msg)
