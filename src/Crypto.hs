{-# LANGUAGE BangPatterns #-}

{-|
@
Salt             = Cryptographic salt
c                = PBKDF2 iteration count
DerivedKey       = PBKDF2(SHA-512, Pass, Salt, c, 16 + 32)
(EncKey, MacKey) = splitAt 16 DerivedKey
IV               = 0
CipherText       = AES-128-CTR(Message, EncKey)
MAC              = HMAC-256(MacKey, SHA-256(Salt) + SHA-256(CipherText)))
@

The HMAC inputs are hashed before concatenation to avoid leaving "gaps" in
the input.
Only the derivation parameters and the ciphertext are hashed, to avoid
leaking any information about the key material or the plain text.

The salt length is set to the output size of the PBKDF2 PRF, per the NIST
recommendation.

The HMAC key length is set to the output size of the hash function, the
sensible maximum according to RFC 2104.

References:

* HMAC: Keyed-Hashing for Message Authentication,
  <https://www.ietf.org/rfc/rfc2104.txt>
-}

module Crypto (
  getSalt,
  guessIterCount,
  encode, decode,
  encrypt, decrypt
  ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad ((<=<))

import Crypto.Hash (SHA256)
import Crypto.MAC (HMAC, hmac)
import Data.Byteable (toBytes)
import qualified Crypto.Cipher.AES       as AES
import qualified Crypto.Hash.SHA256      as SHA256
import qualified Crypto.PBKDF.ByteString as PBKDF

import qualified Data.ByteString.Base64 as Base64
import qualified Data.Serialize         as Serialize

import Control.Exception (evaluate)
import Data.String (fromString)
import System.CPUTime (getCPUTime)

import qualified Data.ByteString      as SB
import qualified Data.ByteString.Lazy as LB

------------------------------------------------------------------------
-- Tuning parameters

guessIterCount :: Double -> IO Int
guessIterCount targetSecs = go 1000
  where
    go !count = do
      t0 <- getCPUTime
      _  <- evaluate (kdf (fromString "PASS") (fromString "SALT") count)
      t1 <- getCPUTime
      if (fromIntegral (t1 - t0) * 1e-12) >= targetSecs
         then return count
         else go (count + 1000)

------------------------------------------------------------------------
-- Serialization

encode
  :: SB.ByteString -- ^ Salt
  -> Int           -- ^ c
  -> SB.ByteString -- ^ Ciphertext
  -> SB.ByteString -- ^ HMAC
  -> SB.ByteString
encode salt c mac enc = Base64.encode . Serialize.runPut $ do
  Serialize.putWord16le (fromIntegral c)
  Serialize.putByteString (SB.concat [ salt, mac, enc ])

decode
  :: SB.ByteString
  -> Either String (SB.ByteString, Int, SB.ByteString, SB.ByteString)
  -- ^ Either error or @(Salt, c, HMAC, Ciphertext)@.
decode = Serialize.runGet (do
  c <- fromIntegral <$> Serialize.getWord16le
  s <- Serialize.getByteString 64
  m <- Serialize.getByteString 32
  e <- Serialize.getByteString =<< Serialize.remaining
  return (s, c, m, e)) <=< Base64.decode

------------------------------------------------------------------------
-- Encryption and decryption

getSalt :: IO SB.ByteString
getSalt = urandom 64

encrypt :: SB.ByteString -- ^ Passphrase
        -> SB.ByteString -- ^ Salt
        -> Int           -- ^ Iteration count
        -> SB.ByteString -- ^ Message
        -> (SB.ByteString, SB.ByteString) -- ^ @(HMAC, Ciphertext)@
encrypt pass salt iter plain =
  let (ekey, hkey) = kdf pass salt iter
      ctx = AES.initAES ekey
      enc = AES.encryptCTR ctx kNONCE plain
      mac = hmac256 hkey (hash256 salt `SB.append` hash256 enc)
  in (mac, enc)

decrypt :: SB.ByteString -- ^ Passphrase
        -> SB.ByteString -- ^ Salt
        -> Int           -- ^ Iteration count
        -> SB.ByteString -- ^ HMAC
        -> SB.ByteString -- ^ Ciphertext
        -> Either String SB.ByteString
decrypt pass salt iter mac' enc =
  let (ekey, hkey) = kdf pass salt iter
      ctx = AES.initAES ekey
      mac = hmac256 hkey (hash256 salt `SB.append` hash256 enc)
      dec = AES.decryptCTR ctx kNONCE enc in
  if mac' == mac then Right dec else Left "HMAC mismatch"

------------------------------------------------------------------------
-- Internals

kdf :: SB.ByteString -> SB.ByteString -> Int -> (SB.ByteString, SB.ByteString)
kdf pass salt c = SB.splitAt 16 (PBKDF.sha512PBKDF2 pass salt c 48)

kNONCE :: SB.ByteString
kNONCE = SB.pack [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]

hash256 :: SB.ByteString -> SB.ByteString
hash256 = SHA256.hash

hmac256 :: SB.ByteString -> SB.ByteString -> SB.ByteString
hmac256 s m = toBytes (hmac s m :: HMAC SHA256)

-- | Read @n@ octets of random data from @/dev/urandom@.
urandom :: Int -> IO SB.ByteString
urandom nbytes = (LB.toStrict . LB.take n') <$> LB.readFile "/dev/urandom"
  where n' = fromIntegral nbytes
