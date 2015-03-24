{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}

{-|
Briefly, the encryption scheme is a variant of the PBES2 encryption scheme,
described in RFC 2898 section 6.2.

@
Pass             = User-supplied passphrase
Salt             = 64 bytes of cryptographic salt
c                = PBKDF2 iteration count

DerivedKey       = PBKDF2(SHA-512, Pass, Salt, c, 16 + 32)
(EncKey, MacKey) = splitAt 16 DerivedKey
IV               = 0
CipherText       = AES-128-CTR(IV, Message, EncKey)
MAC              = HMAC-SHA-256(MacKey, SHA-256(Salt) + SHA-256(CipherText)))
@

The HMAC inputs are hashed before concatenation to avoid leaving "gaps" in
the input.
Only the derivation parameters and the ciphertext are hashed, to avoid
leaking any information about the key material or the plain text.

The salt length is set to the output size of the PBKDF2 PRF.
TODO: explain why this is done.

The HMAC key length is set to the output size of the hash function, the
sensible maximum according to RFC 2104.

References:

* HMAC: Keyed-Hashing for Message Authentication,
  <https://www.ietf.org/rfc/rfc2104.txt>

* PKCS #5: Password-Based Cryptography Specification Version 2.0,
  <https://www.ietf.org/rfc/rfc2898.txt>
-}

module Crypto (
  getSalt,
  guessIterCount,

  encryptAndEncode,
  decodeAndDecrypt,
  recrypt,

#ifdef TEST
  encode, decode, encrypt, decrypt,
#endif
  ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad ((>=>))

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
guessIterCount targetSecs = do
  salt <- getSalt
  let
    pass = fromString "Pass"
    loop !z = do
      t0 <- getCPUTime
      _  <- evaluate (kdf pass salt z)
      t1 <- getCPUTime
      if (fromIntegral (t1 - t0) * 1e-12) >= targetSecs
         then return z
         else loop (z + 1000)
  loop 0

------------------------------------------------------------------------
-- High-level interface

-- | Update passphrase and encryption parameters.
recrypt
  :: SB.ByteString -- ^ Original passphrase
  -> SB.ByteString -- ^ New passphrase
  -> SB.ByteString -- ^ New salt
  -> Int           -- ^ New iteration count
  -> SB.ByteString -- ^ Original encoded ciphertext
  -> Either String SB.ByteString -- ^ Either error or new encoded ciphertext
recrypt origPass newPass newSalt newIter etxt = do
  (salt, c, mac, txt) <- decode etxt
  msg <- decrypt origPass salt c mac txt
  return $! encryptAndEncode newPass newSalt newIter msg

-- | Encrypt the input message and return a base64 encoded string containing
-- the encryption parameters along with the ciphertext.
encryptAndEncode
  :: SB.ByteString -- ^ Passphrase
  -> SB.ByteString -- ^ Salt
  -> Int           -- ^ c
  -> SB.ByteString -- ^ Message
  -> SB.ByteString -- ^ Encoded ciphertext
encryptAndEncode pass salt c = uncurry (encode salt c) . encrypt pass salt c

-- | The inverse of 'encryptAndEncode'.
decodeAndDecrypt
  :: SB.ByteString -- ^ Passphrase
  -> SB.ByteString -- ^ Encoded ciphertext
  -> Either String SB.ByteString -- ^ Either an error or original plaintext
decodeAndDecrypt pass etxt = do
  (salt, c, mac, txt) <- decode etxt
  decrypt pass salt c mac txt

------------------------------------------------------------------------
-- Serialization

encode
  :: SB.ByteString -- ^ Salt
  -> Int           -- ^ c
  -> SB.ByteString -- ^ MAC
  -> SB.ByteString -- ^ Ciphertext
  -> SB.ByteString -- ^ @Base64 (c + Salt + MAC + Ciphertext)@
encode salt c mac txt = Base64.encode . Serialize.runPut $ do
  Serialize.putWord16le (fromIntegral c)
  Serialize.putByteString (SB.concat [ salt, mac, txt ])

decode
  :: SB.ByteString
  -> Either String (SB.ByteString, Int, SB.ByteString, SB.ByteString)
  -- ^ Either error or @(Salt, c, MAC, Ciphertext)@.
decode = Base64.decode >=> Serialize.runGet (do
  c <- fromIntegral <$> Serialize.getWord16le
  s <- Serialize.getByteString 64
  m <- Serialize.getByteString 32
  e <- Serialize.getByteString =<< Serialize.remaining
  return (s, c, m, e))

------------------------------------------------------------------------
-- Encryption and decryption

encrypt :: SB.ByteString -- ^ Passphrase
        -> SB.ByteString -- ^ Salt
        -> Int           -- ^ Iteration count
        -> SB.ByteString -- ^ Message
        -> (SB.ByteString, SB.ByteString) -- ^ @(MAC, Ciphertext)@
encrypt pass salt c plain =
  let (ekey, hkey) = kdf pass salt c
      ctx = AES.initAES ekey
      txt = AES.encryptCTR ctx kNONCE plain
      mac = hmac256 hkey (sha256 salt `SB.append` sha256 txt)
  in (mac, txt)

decrypt :: SB.ByteString -- ^ Passphrase
        -> SB.ByteString -- ^ Salt
        -> Int           -- ^ Iteration count
        -> SB.ByteString -- ^ MAC
        -> SB.ByteString -- ^ Ciphertext
        -> Either String SB.ByteString -- ^ Error message or plaintext
decrypt pass salt c mac' txt =
  let (ekey, hkey) = kdf pass salt c
      ctx = AES.initAES ekey
      mac = hmac256 hkey (sha256 salt `SB.append` sha256 txt)
  in if mac' == mac
     then Right (AES.decryptCTR ctx kNONCE txt)
     else Left "MAC mismatch"

kNONCE :: SB.ByteString
kNONCE = SB.pack [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]

------------------------------------------------------------------------
-- Cryptographic salt

getSalt :: IO SB.ByteString
getSalt = (LB.toStrict . LB.take 64) <$> LB.readFile "/dev/urandom"

------------------------------------------------------------------------
-- Key derivation

kdf
  :: SB.ByteString
  -> SB.ByteString
  -> Int
  -> (SB.ByteString, SB.ByteString)
kdf pass salt c = SB.splitAt 16 (PBKDF.sha512PBKDF2 pass salt c (16 + 32))

------------------------------------------------------------------------
-- Internals

sha256 :: SB.ByteString -> SB.ByteString
sha256 = SHA256.hash

hmac256 :: SB.ByteString -> SB.ByteString -> SB.ByteString
hmac256 s m = toBytes (hmac s m :: HMAC SHA256)
