{-# LANGUAGE OverloadedStrings #-}

{-|
A simple PBES2 construction based on AES-GCM. Briefly, a message is
encrypted by a random key derived from a user-supplied passphrase and a
cryptographic salt. The key is derived using PBKDF2 with a suitable work
factor. The parameters and the ciphertext are authenticated, to ensure
integrity.
-}

module Crypto.PBES2.AES_GCM (
  -- * High-level interface
  doEncryptText,
  doEncryptFile,
  doDecryptText,
  doDecryptFile,

  -- * Pure interface
  decodeAndDecrypt,
  encryptAndEncode,

  -- * Low-level
  encode,
  decode,

  encrypt,
  decrypt,

  deriveKey,
  getSalt,
  ) where

import Control.Applicative

import qualified Data.List as L

import Data.Byteable (Byteable(..))
import Data.String (fromString)
import Data.ByteString (ByteString)
import qualified Data.ByteString as SB
import qualified Data.ByteString.Lazy as LB

import Crypto.Cipher.AES (AES, initAES, encryptGCM, decryptGCM)
import Crypto.Cipher.Types (AuthTag(..))
import Crypto.PBKDF.ByteString (sha512PBKDF2)
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Data.Serialize as Serialize
import qualified Data.ByteString.Base64 as Base64

import System.Directory (doesFileExist, doesDirectoryExist)

------------------------------------------------------------------------
-- Higher-level interface

doDecryptText :: ByteString -> ByteString -> IO ByteString
doDecryptText pass = either fail return . decodeAndDecrypt pass

doDecryptFile :: ByteString -> FilePath -> FilePath -> IO ()
doDecryptFile pass inFile outFile = do
  unlessM (doesFileExist inFile) $
    fail "doDecryptFile: non-existent input file"
  whenM (doesFileExist outFile) $
    fail "doDecryptFile: output file exists; refusing to overwrite"
  SB.writeFile outFile =<< either fail return =<<
    (decodeAndDecrypt pass <$> SB.readFile inFile)

doEncryptText
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Plain
  -> IO ByteString
doEncryptText pass plain =
  encryptAndEncode <$> pure pass <*> getSalt <*> pure plain

doEncryptFile
  :: ByteString -- ^ Pass
  -> FilePath   -- ^ Input file
  -> FilePath   -- ^ Output file
  -> IO ()
doEncryptFile pass inFile outFile = do
  unlessM (doesFileExist inFile) $
    fail "doEncryptFile: non-existent input file"
  whenM (doesFileExist outFile) $
    fail "doEncryptFile: output file exists; refusing to overwrite"
  SB.writeFile outFile =<<
    (encryptAndEncode <$> pure pass <*> getSalt <*> SB.readFile inFile)

unlessM b m = b >>= \r -> if r then return () else m
whenM b m   = b >>= \r -> if r then m else return ()

encryptAndEncode
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Salt
  -> ByteString -- ^ Plain
  -> ByteString -- ^ Encoded parameters and ciphertext
encryptAndEncode pass salt plain = encode salt tag enc
  where (enc, tag) = encrypt pass salt plain

decodeAndDecrypt
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Encoded parameters and ciphertext
  -> Either String ByteString
  -- ^ Either an error (decode/auth) or recovered plaintext
decodeAndDecrypt pass enc =
  case decode enc of
    Left err  -> Left ("decoding error: " ++ err)
    Right (salt, etxt, tag1) ->
      let (plain, tag2) = decrypt pass salt etxt in
      if tag1 == tag2
        then Right plain
        else Left "authentication error: tag mismatch"

------------------------------------------------------------------------
-- Serialization

encode
  :: ByteString -- ^ Salt
  -> AuthTag    -- ^ Authentication tag
  -> ByteString -- ^ Ciphertext
  -> ByteString -- ^ Encoded paramteres and ciphertext
encode salt tag enc = Base64.encode (SB.concat [ salt, toBytes tag, enc ])

decode
  :: ByteString -- ^ Encoded parameters and ciphertext
  -> Either String (ByteString, ByteString, AuthTag)
decode x = case Base64.decode x of
  Left err  -> Left err
  Right res -> let (salt, tl1) = SB.splitAt kSALTLEN res
                   (tag, enc)  = SB.splitAt kTAGLEN tl1 in
               Right (salt, enc, AuthTag tag)

------------------------------------------------------------------------
-- Encrypt/decrypt

encrypt
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Salt
  -> ByteString -- ^ Plain
  -> (ByteString, AuthTag)
encrypt pass salt = withDerivedKey pass salt encryptGCM

decrypt
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Salt
  -> ByteString -- ^ Ciphertext
  -> (ByteString, AuthTag)
decrypt pass salt = withDerivedKey pass salt decryptGCM

withDerivedKey
  :: ByteString -- ^ Pass
  -> ByteString -- ^ Salt
  -> (AES -> ByteString -> ByteString -> ByteString -> a) -- ^ Operation
  -> (ByteString -> a) -- ^ Operation on input
withDerivedKey pass salt f =
  let key = deriveKey pass salt
      ctx = initAES key
      aad = toBytes salt
  in f ctx kNONCE aad

------------------------------------------------------------------------
-- Key derivation.

-- | Get cryptographic key derivation salt.
getSalt :: IO ByteString
getSalt = takeLBS kSALTLEN <$> LB.readFile "/dev/urandom"

{-|
Derive encryption key from a passphrase and a cryptographic salt.

Re-using salts undermines security, re-using @(Pass, Salt)@ destroys it.
See the PBKDF2 RFC section 4 for details on choosing salts.
-}
deriveKey
  :: ByteString -- ^ Passphrase
  -> ByteString -- ^ Cryptographic salt
  -> ByteString -- ^ Encryption key
deriveKey pass salt = sha512PBKDF2 pass salt 10000 kKEYLEN

takeLBS :: Int -> LB.ByteString -> SB.ByteString
takeLBS n = LB.toStrict . LB.take (fromIntegral n)
{-# INLINE takeLBS #-}

------------------------------------------------------------------------
-- Constants

-- | A fixed \"nonce\".
kNONCE :: ByteString
kNONCE = SB.pack [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]

-- | Authentication tag length, in octets.
kTAGLEN :: Int
kTAGLEN = 16

-- | Derived key length, in octets.
kKEYLEN :: Int
kKEYLEN = 32

-- | Cryptographic key derivation salt length, in octets.
kSALTLEN :: Int
kSALTLEN = 64 -- arbitrarily set to the output size of the PRF

kKDFNAME :: ByteString
kKDFNAME = "PBKDF2"

kPRFNAME :: ByteString
kPRFNAME = "SHA512"

kENCNAME :: ByteString
kENCNAME = "AES-GCM"
