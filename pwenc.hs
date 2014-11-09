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

main :: IO ()
main = print =<< uncurry cmdEnc =<<
       (Line.runInputT Line.defaultSettings $ (,) <$> getPassword
                                                  <*> getInputLine)
  where
    getPassword  = (fromString . fromMaybe "") <$> Line.getPassword (Just '*') "Password: "
    getInputLine = (fromString . fromMaybe "") <$> Line.getInputLine "Secret: "
