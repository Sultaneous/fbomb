#!/usr/bin/python

#"fsend" by Karim Sultan, September 2020
# fsend is a client for the FBomb Protocol
# It communicates with a server to transfer a file.
# This protocol makes it easy to drop f-bombs across machines.

# FBOMB Particulars:
# -> Connect to server
#     Client               Server
#     HI <CID>
#                          OK <SID>
#     FSEND <META>
#                          OK <Proceed> | NOK <Message>
#     <DATA>
#                          OK <Received> | NOK <Message>
#     BYE <CID> [CLOSE]
#                          [CLOSE]
# See FBomb documentation for details.

import socket
import signal
import glob
import types
import os
import hashlib
import getopt
from gamzia.filedescriptor import *
from gamzia.accountmanager import AccountManager
from gamzia.timer import Timer
from gamzia.colours import Colours as C
import sys
argv=sys.argv
argc=(len(argv))

# Constants
APP_NAME    = "fsend"
APP_VERSION = 1.0
APP_AUTHOR  = "Karim Sultan"
APP_DATE    = "September 2020"
APP_EMAIL   = "karimsultan@hotmail.com"
APP_BLURB   = "Client CLI program for file transfer using FBOMB protocol."
APP_SYNTAX  = "Syntax: fsend [options] <file1> [<file2> ... <fileN>]"

# Settings defaults
DEF_ENC     = "utf-8"          # Default text encoding type
DEF_VERBOSE = False            # T/F for extra detail
DEF_HOST    = "localhost"      # The server's hostname or IP address
DEF_PORT    = 33333            # The port used by the server
DEF_MODE    = FILEMODE.BINARY  # Default file mode for transfer
DEF_DEBUG   = False            # Sets debug mode; use "--DEBUG" on command line

# Global
FLAG_KILL = False

#*************************************************************************
# The configuration class houses parameter and initialization data
# which configures the client.
class Config:
   def __init__(self):
      self.host=DEF_HOST
      self.port=DEF_PORT
      self.filename=""
      self.filelist=[]
      self.verbose=False
      self.filemode=FILEMODE.BINARY
      self.cid=socket.gethostname()
      self.credentials=""

      # Private attributes
      self._chunk=4096
      self._sock=None
      self._timer=None
      self._DEBUG=DEF_DEBUG

   # Uses reflection to create a dictionary of public atributes
   # Skips any methods or functions or internals.
   def toDictionary(self, showprivate=False):
      d={}
      s=dir(self)
      i=0

      while True:
         if s[i].startswith("__") and s[i].endswith("__"):
            # Attribute is an internal, remove
            s.pop(i)
         elif (s[i].startswith("_") and not showprivate):
            # Attribute is a private variable or method, remove
            s.pop(i)
         elif (isinstance(getattr(self, s[i]), types.MethodType) or
               "function" in str(type(getattr(self, s[i])))):
            # Attribute is a method/function, remove
            s.pop(i)
         else:
            # Attribute is a value attribute, continue
            i+=1
         if (i>=len(s)):
            break
      for key in s:
         d[key]=getattr(self, key)
      return (d)

   def toString(self, showprivate=False):
      s=""
      d=self.toDictionary(showprivate)
      for key, value in d.items():
         s+=f"{key}={value}\n"
      return(s)

#*************************************************************************

# Traps control C for a smooth exit
def onSignal_kill(sig, frame):
   global FLAG_KILL
   FLAG_KILL=True
   print ()
   print (f"{C.bdr}{C.cly}CTRL-C Detected!")
   print (f"Aborting communications and exiting...{C.off} ")
   # This is critical in order to kill the listener and free address/port.
   if not config._sock==None:
      config._sock.close()
   print ()
   exit ()

# Outputs a message for a serious error, and terminates program
# Use this for fatal errors only!
def error(message):
   if (not FLAG_KILL):
      print(f"{C.clr}An error has occurred!");
      print(f"{C.clm}{message}{C.coff}{C.boff}")
      if (config._sock):
         config._sock.close()
      exit()

# "Pips up" to let you know something minor happened, doesn't impact
# program flow.  Should only be called if verbose is True.
# This method is intended for non-fatal errors.
def pip(message):
   print(f"{C.clg}{C.bdg}{message}{C.off}")

# Outputs a message to screen only if in verbose mode OR if show==true
def note(message, show=False):
   if (config.verbose or show==True):
      print(f"{C.clc}{C.boff}{message}{C.off}")

# Just outputs a message regardless of verboseness
def notex(message):
   note(message, show=True)

# Shows the info, blurb, syntax and options screen.
def showHelp():
   # This title line is now output by main() on all usage, so comment for now
   #print (f"{C.cly}{C.bdb}{APP_NAME}{C.boff} v{APP_VERSION} by {APP_AUTHOR} {APP_DATE} {APP_EMAIL}")
   print (f"{APP_BLURB}")
   print ()
   print (f"{C.clg}{APP_SYNTAX}");
   print ()
   print (f"{C.clc}Where:")
   print (f"{C.clg}-?, --help:    {C.clc}This help screen")
   print (f"{C.clg}-v, --verbose: {C.clc}Enable verbose mode")
   print (f"{C.clg}-h, --host:    {C.clc}Target server  ({C.clm}default {C.clc}is {C.cwh}{DEF_HOST}{C.clc})")
   print (f"{C.clg}-p, --port:    {C.clc}Target port    ({C.clm}default {C.clc}is {C.cwh}{DEF_PORT}{C.clc})")
   print (f"{C.clg}-m, --mode:    {C.clc}ASCII | BINARY ({C.clm}default {C.clc}is {C.cwh}{DEF_MODE.name}{C.clc})")
   print (f"{C.clg}-c, --cid:     {C.clc}Set client ID  ({C.clm}default {C.clc}is {C.cwh}{socket.gethostname()}{C.clc})")
   print (f"{C.clg}-u, --user:    {C.clc}Authenticate   ({C.clm}syntax  {C.clc}is {C.cwh}user:password{C.clc})")
   print (f"{C.clg} --version:    {C.clc}Reports program version number and exits")
   print (f"{C.clg}{C.bdg}NOTE:{C.boff} {C.clc}Filename must be provided as an argument")
   print (f"{C.clgy}Parameter values can be after '=' or a space (ie, -p 10000 or -p=10000)")
   print (f"{C.coff}")
   exit()


# Parses options, switches and args.  Does validation.  Populates the config
# structure which contains the info need to do the file transfer.
def parseCommandLine():
   if argc<2:
      showHelp()

   # Single switch options are listed with a ":" suffix only if they expect a value.
   # Extended options (--) must have a "=" suffix if value is expected
   try:
       opts, args =getopt.getopt(argv[1:],
        "?SvDh:p:m:c:u:",
        ["help","version","verbose","host=","port=", "mode=", "cid=",
         "DEBUG", "user="])
   except getopt.GetoptError as e:
      print(f"Arguments error: {e.msg} {e.opt}")
      showHelp()

   # We store retrieved arguments in a config structure
   config=Config()
   for opt, arg in opts:
      if (opt in ("-?", "--help")):
         showHelp()

      # This option check must come before version check
      # as "-v" is in version, and I'm sticking to the "in" patern
      # (it makes expansion easy)
      elif (opt in("-v", "--verbose")):
         config.verbose=True

     # Debugging flag
      elif (opt in ("-D", "--DEBUG")):
         config._DEBUG=True

      # Show version and then exit immediately
      elif (opt in ("--version")):
         print(f"{C.clc}Version: {C.clg}{APP_VERSION}{C.off}")
         exit()

      # Default is FILEMODE.BINARY
      elif (opt in ("-m", "--mode")):
         amode = arg.upper()
         if (amode=="ASCII"):
            config.filemode=FILEMODE.ASCII
         else:
            if (not arg.upper()=="BINARY"):
               pip (f"File mode: {arg} is not recognized. Defaulting to BINARY.")
            config.filemode=FILEMODE.BINARY

      # Sets server host.  Can be a resolvable name, or IP address
      elif (opt in ("-h", "--host")):
         config.host=arg

      # Sets server port to connect to.
      elif (opt in ("-p", "--port")):
         config.port=int(arg)

      # Sets the client ID; default is hostname
      elif (opt in ("-c", "--cid")):
         config.cid=arg.strip()

      # Sets the credentials
      elif (opt in ("-u", "--user")):
         config.credentials=arg.strip()

      # Greetings are always welcome
      elif (opt in ("-S")):
         pip(f"{C.bdr}{C.cly}Sultaneous sends salutations.{C.off}")
         exit()

   filelist=[]
   for arg in args:
      for file in glob.glob(arg):
         filelist.append(file)
   config.filelist=filelist
   return(config)


# Constructs a file descriptor object to send to server as meta data
def setMetaData(config):
   fd=FileDescriptor()
   fd.filename=config.filename
   fd.filemode=config.filemode
   fd.length=os.path.getsize(fd.filename)
   fd.timestamp=time.ctime(os.path.getctime(fd.filename))
   fd.hashtype=HASHTYPE.SHA256
   with open(fd.filename, "rb") as file:
      fd.hash=hashlib.sha256(file.read()).hexdigest()
   return(fd)


# Sends a protocol message to server
def sendRequest(sock, msg):
   if (not msg.endswith("\n")):
      msg+="\n"
   data=msg.encode(DEF_ENC)
   try:
      # blocks until all data has been sent
      sock.sendall(data)
      note(f"{C.cly}[{config._timer.peek():.5f} SENT] {C.clgy}{msg.rstrip()}{C.off}")
   except socket.error as e:
      error(f"Network error occurred on send: {e}")
   return


# Gets a protocol response
def getResponse(sock):
   try:
      # Client will use sendall so we don't need to loop on data
      data=sock.recv(1024)
      msg=data.decode(DEF_ENC)
      note(f"{C.cly}[{config._timer.peek():.5f} RECV] {C.cwh}{msg.rstrip()}")
   except socket.error as e:
      error(f"Network error occurred on receive: {e}")
   return(msg)


def transmitAscii(sock, fd):
   notex(f"{C.clc}Sending file {C.cwh}{fd.filename} {C.clc}in {C.clr}ASCII{C.clc} mode.")
   file=open(fd.filename, "r")
   bytes=0
   while True:
      line=file.readline()
      if not line:
         break
      data=line.encode(DEF_ENC)
      sock.sendall(data)
      bytes+=len(data)
      progress=int((bytes/fd.length)*100)
      print(f"{C.cly}Progress: {C.cwh}{progress:4}%", end='\r', flush="True")
   file.close()
   notex(f"{C.cly}[{config._timer.peek():.5f} SENT] {C.clr}ASCII {C.clc}mode file: {C.clg}{fd.length:,} {C.clc}bytes.") 

def transmitBinary(sock, fd):
   notex(f"{C.clc}Sending file {C.cwh}{fd.filename} {C.clc}in {C.clr}BINARY{C.clc} mode.")
   file=open(fd.filename, "rb")
   chunks=0
   bytes=0
   while True:
      chunk=file.read(config._chunk)
      if not chunk:
         break
      chunks+=1
      sock.sendall(chunk)
      bytes+=len(chunk)
      progress=int((bytes/fd.length)*100)
      print(f"{C.cly}Progress: {C.cwh}{progress:4}%", end='\r', flush="True")
   file.close()
   notex(f"{C.cly}[{config._timer.peek():.5f} SENT] {C.clr}BINARY {C.clc}mode file: {C.clg}{fd.length:,} {C.clc}bytes.")

# Extracts a user and password from string if present
# Returns boolean, string, string.
# NOTE: This method does not use a good pattern.  It can
# be decomposed and refactored into a nicer approach.
# BUT it was implemented like this during agile development
# and works so was kept.
# TODO: Refactor / Decompose and clean
def extractUP(s):
   # Init
   response=False
   user=""
   password=""

   # Validate
   if (not ":" in s):
      return (False, user, password)

   # Strip
   s=s.strip()

   if (s.startswith(":") or s.endswith(":")):
       return (False, user, password)

   ss=s.split(":")
   if (len(ss)<2):
      return (False, user, password)

   user=ss[0]
   password=ss[1]
   return(True, user, password)


# Tries to connect to the server and manage the protocol
def fbomb(config, fd):
   try:
      sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      config._sock=sock
      sock.connect((config.host, config.port))
      notex(f"Connected to {config.host}:{config.port}")

      # Send / Rec protocol
      if (config.credentials==""):
         sendRequest (sock, f"HI {config.cid}")
      else:
         valid, user, password = extractUP(config.credentials)
         if (valid):
            passwordHash = AccountManager.saltPassword(user, password)
            sendRequest (sock, f"Hi {user}:{passwordHash}")
         else:
            sendRequest (sock, f"HI {config.cid}")
      msg=getResponse(sock)

      # Send meta / request permission to send file
      if (msg.startswith("OK ")):
         sendRequest (sock, fd.serialize())
         msg=getResponse(sock)
      else:
         error(f"Server denied connection: {msg}")

      if (msg.startswith("OK ")):
         if (fd.filemode == FILEMODE.ASCII):
            transmitAscii(sock, fd)
         else:
            transmitBinary(sock, fd)
      else:
         error(f"Server denied transmit request: {msg}")

      # Bye bye
      getResponse(sock)
      sendRequest (sock, "BYE")

   except socket.error as e:
      error(f"Network error occurred on connect: {e}")
   finally:
      sock.close()


# The main line of execution
def main():
   # Register signal handler
   signal.signal(signal.SIGINT, onSignal_kill)

   print (f"{C.cly}{C.bdb}{APP_NAME}{C.boff} v{APP_VERSION} by {APP_AUTHOR} {APP_DATE} {APP_EMAIL}{C.off}")
   global config
   config=parseCommandLine()

   if (config._DEBUG):
      print (config.toString(showprivate=True))
      exit()

   # Send all files in filelist
   sent=0
   opTimer=Timer()
   opTimer.start()
   for filename in config.filelist:
      config.filename=filename

      # File to send must exist
      if not os.path.isfile(config.filename):
         error("Invalid filename: "+config.filename)

      note(f"{C.clg}{C.bdg}Verbose Mode{C.boff}{C.clc} is on. Ouputting details.")
      note(f"{C.clc}Outputting client configuration:")
      note(f"{C.clgy}{config.toString()}{C.coff}")

      fd = setMetaData(config)
      note(f"{C.clc}Outputting file descriptor:")
      note(f"{C.clgy}{fd.toString()}{C.coff}")
      note(f"{C.clc}JSON Serialized Form for Wire Transit:")
      note(f"{C.clgy}{fd.serialize()}{C.coff}")

      config._timer=Timer()
      config._timer.start()
      notex(f"{C.clg}Attempting to connect to {config.host}:{config.port}{C.off}")
      fbomb (config,fd)
      sent+=1
      config._timer.stop()
      notex(f"{C.clc}Done. Completed in {C.clg}{config._timer.elapsed():.5f}{C.off} seconds.")
   opTimer.stop()
   notex(f"{C.off}File send complete.  Sent {C.cly}{sent}{C.off} files in {C.clg}{opTimer.elapsed():.5f}{C.off} seconds.")
#END

# Run program
if __name__ == "__main__":
   main()

