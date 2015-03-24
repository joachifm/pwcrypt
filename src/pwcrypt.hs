{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto

import Control.Applicative
import Data.Maybe (fromMaybe)

import Data.String (fromString)
import qualified Data.ByteString as SB

import Data.Monoid
import Options.Applicative

import System.Environment (getArgs)
import qualified System.Console.Haskeline as Line

data EncOptions = EncOptions
  { encInpFile :: FilePath
  , encOutFile :: FilePath
  , encParamTargetTime :: Double
  } deriving (Show)

data DecOptions = DecOptions
  { decInpFile :: FilePath
  , decOutFile :: FilePath
  } deriving (Show)

data RecOptions = RecOptions
  { recInpFile :: FilePath
  , recOutFile :: FilePath
  } deriving (Show)

data Command
  = Encrypt EncOptions
  | Decrypt DecOptions
  | Recrypt RecOptions
    deriving (Show)

data Options = Options
  { optCommand :: Command
  } deriving (Show)

options :: Parser Options
options = Options <$>
  subparser (
    command "enc" (info (Encrypt <$> encOpts) ( progDesc "encrypt" )) <>
    command "dec" (info (Decrypt <$> decOpts) ( progDesc "decrypt" )) <>
    command "rec" (info (Recrypt <$> recOpts) ( progDesc "recrypt" ))
  )
  where
    encOpts = EncOptions <$>
      strOption (
        long "infile" <>
        metavar "FILE" <>
        help "Input file"
        ) <*>
      strOption (
        long "outfile" <>
        metavar "FILE" <>
        help "Output file"
        ) <*>
      option double (
        long "target-time" <>
        metavar "FLOAT" <>
        help "Target time parameter" <>
        value (0.2::Double)
        )

    decOpts = DecOptions <$>
      strOption (
        long "infile" <>
        metavar "FILE" <>
        help "Input file"
        ) <*>
      strOption (
        long "outfile" <>
        metavar "FILE" <>
        help "Output file"
        )

    recOpts = RecOptions <$> pure "" <*> pure ""

    double :: ReadM Double
    double = auto

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
main = execParser opts >>= \x -> case optCommand x of
  Encrypt os -> cmdEnc [encInpFile os, encOutFile os]
  Decrypt os -> cmdDec [decInpFile os, decOutFile os]
  Recrypt _  -> return ()
  where
    opts = info (helper <*> options)
      ( fullDesc <>
        progDesc "File encryption utility" <>
        header "pwcrypt" )
