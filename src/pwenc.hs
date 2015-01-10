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
  let (mac, enc) = encrypt pass salt iter plain
  SB.writeFile outFile $ encode salt iter mac enc
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
  ed <- decode <$> SB.readFile inFile
  case ed of
    Left err  -> error ("decoding error: " ++ err)
    Right (salt, iter, mac, enc) -> do
      pass <- Line.runInputT Line.defaultSettings (getPassword "Enter passphrase: ")
      case decrypt pass salt iter mac enc of
        Left err -> error ("decryption error: " ++ err)
        Right x  -> SB.writeFile outFile x
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
