{-# LANGUAGE OverloadedStrings #-}

module CryptoSpec (spec) where

import Crypto

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Identity
import Test.Hspec
import Test.Hspec.Core.Spec

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

io = SpecM . liftIO
