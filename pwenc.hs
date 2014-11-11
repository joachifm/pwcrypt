{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Control.Applicative
import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString as SB

import System.Environment (getArgs)
import qualified System.Console.Haskeline as Line

------------------------------------------------------------------------
-- Command wrappers

cmdEnc :: SB.ByteString -- ^ Passphrase
       -> SB.ByteString -- ^ Plaintext
       -> IO (SB.ByteString, Int, SB.ByteString)
cmdEnc pass plain = do
  salt <- getSalt
  iter <- guessIterCount
  return $ encode salt iter (encrypt pass salt iter plain)

------------------------------------------------------------------------
-- Command-line interface.

getPassword :: IO SB.ByteString
getPassword = Line.runInputT Line.defaultSettings loop
  where
    input p = fromString. fromMaybe "" <$> Line.getPassword (Just '*') p
    loop = do
      pw1 <- input "Enter passphrase: "
      pw2 <- input "Verify          : "
      if pw1 == pw2
        then return pw1
        else Line.outputStrLn "Mismatch" >> loop

main :: IO ()
main = do
  args <- getArgs
  case args of
    [inFile, outFile] -> do
      pw <- getPassword
      cs <- SB.readFile inFile
      es <- cmdEnc pw cs
      SB.writeFile outFile (fromString $ show es)
    _ -> error "Missing arguments\nUsage: pwenc <infile> <outfile>"
    
