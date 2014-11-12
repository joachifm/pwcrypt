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

import Control.Applicative ((<$>), (<*>))

import Data.Maybe (fromMaybe)

import System.CPUTime (getCPUTime)
import Control.Exception (evaluate)

import qualified Crypto.Cipher.AES       as AES
import qualified Crypto.PBKDF.ByteString as PBKDF

import Data.String (fromString)
import qualified Data.ByteString       as SB
import qualified Data.ByteString.Char8 as SB8
import qualified Data.ByteString.Lazy  as LB

------------------------------------------------------------------------
-- Random.

-- | Read @n@ octets of random data from @/dev/urandom@.
urandom :: Int -> IO SB.ByteString
urandom nbytes = (LB.toStrict . LB.take n') <$> LB.readFile "/dev/urandom"
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
      if (fromIntegral (t1 - t0) * 1e-12) >= 0.2 -- of a second
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

encode :: (SB.ByteString, -- ^ Salt
           Int,           -- ^ Iteration count
           SB.ByteString) -- ^ Ciphertext
       -> SB.ByteString
encode (salt, iter, enc) = SB.concat [ salt, fromString (show iter), enc ]

decode :: SB.ByteString -> (SB.ByteString, Int, SB.ByteString)
decode x0 =
  let (salt, xs1) = SB.splitAt kHASHSIZE x0
      (iter, txt) = SB.span (\c -> c >= 48 && c <= 57) xs1
  in (salt, read $ SB8.unpack iter, txt)
