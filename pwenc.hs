{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Control.Applicative
import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString as SB

import System.Environment (getArgs)
import qualified System.Console.Haskeline as Line

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

cmdEnc :: [String] -> IO ()
cmdEnc [inFile, outFile] = do
  plain <- SB.readFile inFile
  pass <- getPassword
  salt <- getSalt
  iter <- guessIterCount
  let enc = fromString . show . encode salt iter $ encrypt pass salt iter plain
  SB.writeFile outFile enc
cmdEnc _ = error "Missing arguments\nUsage: pwenc enc <infile> <outfile>"

main :: IO ()
main = do
  args <- getArgs
  case args of
    (cmd:xs) ->
      case cmd of
        "enc" -> cmdEnc xs
        _ -> error "Unknown command"
    _ -> error "Missing command\nUsage: pwemc {enc|dec} [options]"
