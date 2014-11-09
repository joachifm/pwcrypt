{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Control.Applicative
import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString as SB

import qualified System.Console.Haskeline as Line

------------------------------------------------------------------------
-- Command wrappers

cmdEnc :: SB.ByteString
       -> SB.ByteString
       -> IO (SB.ByteString, Int, SB.ByteString)
cmdEnc pass plain = do
  salt <- getSalt
  iter <- guessIterCount
  return $ encode salt iter (encrypt pass salt iter plain)

------------------------------------------------------------------------
-- Command-line interface.

getFileContents "-" = SB.getContents
getFileContents fn  = SB.readFile fn

getPassword "" = Line.runInputT Line.defaultSettings $
  fromString . fromMaybe "" <$> Line.getPassword (Just '*') "Password: "
getPassword fn = SB.readFile fn

main :: IO ()
main = print =<< uncurry cmdEnc =<<
  ((,) <$> getPassword "" <*> getFileContents "-")
