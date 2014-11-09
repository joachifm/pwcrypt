{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString        as SB
import qualified Data.ByteString.Base64 as Base64

import qualified System.Console.Haskeline as Line

------------------------------------------------------------------------
-- Command wrappers

cmdEnc :: SB.ByteString
       -> SB.ByteString
       -> IO (SB.ByteString, SB.ByteString, Int)
cmdEnc pass plain = do
  salt <- getSalt
  iter <- guessIterCount
  return (Base64.encode (encrypt pass salt iter plain),
          Base64.encode salt,
          iter)

------------------------------------------------------------------------
-- Command-line interface.

main :: IO ()
main = do
  print =<< uncurry cmdEnc =<< (Line.runInputT Line.defaultSettings $ do
    pw <- getPassword
    se <- getInputLine
    return (fromString pw, fromString se))
  where
    getPassword  = fromMaybe "" `fmap` Line.getPassword (Just '*') "Password: "
    getInputLine = fromMaybe "" `fmap` Line.getInputLine "Secret: "
