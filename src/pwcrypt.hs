{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Control.Applicative
import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString as SB

import System.Environment (getArgs)
import qualified System.Console.Haskeline as Line

getPassword :: String -> Line.InputT IO SB.ByteString
getPassword p = fromString . fromMaybe "" <$> Line.getPassword (Just '*') p

cmdEnc :: [String] -> IO ()
cmdEnc [inFile, outFile] = do
  plain <- SB.readFile inFile
  pass <- Line.runInputT Line.defaultSettings loop
  salt <- getSalt
  iter <- guessIterCount 0.2
  SB.writeFile outFile $ encryptAndEncode pass salt iter plain
  where
    loop = do
      pw1 <- getPassword "Enter passphrase: "
      pw2 <- getPassword "Verify          : "
      if pw1 == pw2
         then return pw1
         else Line.outputStrLn "Mismatch" >> loop
cmdEnc _ = error "Missing arguments\nUsage: pwcrypt enc <infile> <outfile>"

cmdDec :: [String] -> IO ()
cmdDec [inFile, outFile] = do
  pass <- Line.runInputT Line.defaultSettings (getPassword "Enter passphrase: ")
  either fail (SB.writeFile outFile) =<< decodeAndDecrypt pass <$> SB.readFile inFile
cmdDec _ = error "Missing arguments\nUsage: pwcrypt dec <infile> <outfile>"

main :: IO ()
main = do
  args <- getArgs
  case args of
    (cmd:xs) ->
      case cmd of
        "enc" -> cmdEnc xs
        "dec" -> cmdDec xs
        _ -> error "Unknown command"
    _ -> error "Missing command\nUsage: pwcrypt {enc|dec} [options]"
