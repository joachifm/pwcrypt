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
    command "enc" (info (helper <*> (Encrypt <$> encOpts)) ( progDesc "encrypt" )) <>
    command "dec" (info (helper <*> (Decrypt <$> decOpts)) ( progDesc "decrypt" )) <>
    command "rec" (info (helper <*> (Recrypt <$> recOpts)) ( progDesc "recrypt" ))
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
      option auto (
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

getPassword :: String -> Line.InputT IO SB.ByteString
getPassword p = fromString . fromMaybe "" <$> Line.getPassword (Just '*') p

getNewPassword :: Line.InputT IO SB.ByteString
getNewPassword = do
      pw1 <- getPassword "Enter passphrase: "
      pw2 <- getPassword "Verify          : "
      if pw1 == pw2
         then return pw1
         else Line.outputStrLn "Mismatch" >> getNewPassword

cmdEnc :: EncOptions -> IO ()
cmdEnc os = do
  plain <- SB.readFile (encInpFile os)
  pass <- Line.runInputT Line.defaultSettings getNewPassword
  salt <- getSalt
  iter <- guessIterCount (encParamTargetTime os)
  SB.writeFile (encOutFile os) $ encryptAndEncode pass salt iter plain

cmdDec :: DecOptions -> IO ()
cmdDec os = do
  pass <- Line.runInputT Line.defaultSettings (getPassword "Enter passphrase: ")
  either fail (SB.writeFile (decOutFile os)) =<< decodeAndDecrypt pass <$> SB.readFile (decInpFile os)

main :: IO ()
main = execParser opts >>= \x -> case optCommand x of
  Encrypt os -> cmdEnc os
  Decrypt os -> cmdDec os
  Recrypt _  -> return ()
  where
    opts = info (helper <*> options)
      ( fullDesc <>
        progDesc "File encryption utility" <>
        header "pwcrypt" )
