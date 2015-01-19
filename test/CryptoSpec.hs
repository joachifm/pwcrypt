{-# LANGUAGE OverloadedStrings #-}

module CryptoSpec (spec) where

import Crypto

import Control.Monad.IO.Class (liftIO)
import Test.Hspec
import Test.Hspec.Core.Spec (SpecM(..))

spec :: Spec
spec = do
  salt <- io getSalt
  let pass = "Pass"
      mesg = "Mesg"
      c    = 10
  let (mac, txt) = encrypt pass salt c mesg

  describe "decrypt" $ do
    it "retrieves the plaintext" $ do
      decrypt pass salt c mac txt `shouldBe` Right mesg

  describe "decode" $ do
    it "deserializes an encoded entry" $ do
      let enc = encode salt c mac txt
      decode enc `shouldBe` Right (salt, c, mac, txt)

  describe "decodeAndDecrypt" $ do
    it "decodes, then decrypts" $ do
      let enc = encryptAndEncode pass salt c mesg
      decodeAndDecrypt pass enc `shouldBe` Right mesg

  describe "recrypt" $ do
    newSalt <- io getSalt
    it "updates the passphrase and encryption parameters" $ do
      let origEnc = encryptAndEncode pass salt c mesg
          newEnc  = encryptAndEncode "NewPass" newSalt 1024 mesg
      recrypt pass "NewPass" newSalt 1024 origEnc `shouldBe` Right newEnc

    it "returns the original if the parameters do not change" $ do
      let origEnc = encryptAndEncode pass salt c mesg
      recrypt pass pass salt c origEnc `shouldBe` Right origEnc

io :: IO r -> SpecM a r
io = SpecM . liftIO
