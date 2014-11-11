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
  iter <- guessIterCount
  let enc = fromString . show . encode salt iter $ encrypt pass salt iter plain
  SB.writeFile outFile enc
  where
    loop = do
      pw1 <- getPassword "Enter passphrase: "
      pw2 <- getPassword "Verify          : "
      if pw1 == pw2
         then return pw1
         else Line.outputStrLn "Mismatch" >> loop
cmdEnc _ = error "Missing arguments\nUsage: pwenc enc <infile> <outfile>"

cmdDec :: [String] -> IO ()
cmdDec [inFile, outFile] = do
  Right (salt, iter, enc) <- decode . read <$> readFile inFile
  pass <- Line.runInputT Line.defaultSettings (getPassword "Enter passphrase: ")
  let dec = decrypt pass salt iter enc
  SB.writeFile outFile dec
cmdDec _ = error "Missing arguments\nUsage: pwenc dec <infile> <outfile>"

main :: IO ()
main = do
  args <- getArgs
  case args of
    (cmd:xs) ->
      case cmd of
        "enc" -> cmdEnc xs
        "dec" -> cmdDec xs
        _ -> error "Unknown command"
    _ -> error "Missing command\nUsage: pwemc {enc|dec} [options]"
