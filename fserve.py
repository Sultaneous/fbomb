#!/usr/bin/python

#"fserve" by Karim Sultan, September 2020
# fsend is a server (receiver) for the FBomb Protocol
# It communicates with a client (fsend) to transfer a file.
# This protocol makes it easy to drop f-bombs across machines.
#
# This design handles a single connection at a time but accepts
# backlogs. It is meant for individual use, not to serve
# concurrent users.
#
# FBOMB Particulars:
# -> Connect to server
#     Client                Server
#     HI <user:pwd>
#                           OK <SID> | NOK <Message>
#     FSEND <META>
#                           OK <Proceed> | NOK <Message>
#     <DATA>
#                           OK <Received> | NOK <Message>
#     BYE <CID> [CLOSE]
#                           [CLOSE]
#
# Messages are request / response based.
# Format is:
# [OPCODE] [TOKEN] " | " (optional message separator) <message> (optional message)
# Except for data which is sent in serial chunks.
# See FBomb documentation for details.

# NOTE: Avoid using "print" when possible.  Instead, use one of the
# following. They apply formatting, trap the verbose flag, and log data:
#
# pip(msg)              for an important success message (green on green)
# pip(msg, alert=True)  for important warning messages (red on red)
# note(msg)             for loggable verbose mode only messages
# notex(msg)            for loggable all times message

import re
import types
import errno
import datetime
import ntpath
import socket
import signal
import os
import hashlib
import getopt
from gamzia.timer import Timer
from gamzia.colours import Colours as C
from gamzia.filedescriptor import *
from gamzia.accountmanager import AccountManager
import sys
argv=sys.argv
argc=len(argv)

# App Info Constants
APP_NAME    = "fserve"
APP_VERSION = 1.0
APP_AUTHOR  = "Karim Sultan"
APP_DATE    = "September 2020"
APP_EMAIL   = "karimsultan@hotmail.com"
APP_BLURB   = "Server program for file transfer using FBOMB protocol.\n" \
              "Non-threaded version; blocking, uses connection queueing."
APP_SYNTAX  = "Syntax: fserve [options] <inbound directory>"

# Settings defaults
DEF_ENC       = "utf-8"        # Default text encoding type
DEF_HOST      = "localhost"    # The server's hostname or IP address
DEF_PORT      = 33333          # The port used by the server
DEF_OVERWRITE = False          # Abort if file already exists in inbound dir.
DEF_ALLOWSUBS = False          # Abort if inbound filename includes a subdir
DEF_MAXDEPTH  = 3              # If allow sub dirs, max hierarchy depth permitted
DEF_VERBOSE   = False          # T/F for extra detail
DEF_LOGGING   = False          # Logs output to file
DEF_LOGFILE   = "fbomb.log"    # Default log file
DEF_HOME      = "pub"          # Default home directory for inbound files
DEF_ACCOUNTDB = "fb_accounts.db"  # Default accounts database
DEF_AUTH      = True           # Require login?

# Global
FLAG_KILL = False
FLAG_LOGOPEN = False
logfilehandle = None

#Enums
class ACTMGR_ACTIONS(Enum):
   ADD_USER    = 1
   LIST_USERS  = 2
   DELETE_USER = 3
   UPDATE_USER = 4

#*************************************************************************
# The configuration class houses parameter and initialization data
# which configures the client.
# NOTE: Private variables must be prefixed with "_".  ToDictionary() relies
# on this.
class Config:
   def __init__(self):
      # These are the public properties
      self.host=DEF_HOST
      self.port=DEF_PORT
      self.home=DEF_HOME+os.path.sep
      self.isverbose=DEF_VERBOSE
      self.isoverwrite=DEF_OVERWRITE
      self.islogging=DEF_LOGGING
      self.logfile=DEF_LOGFILE
      self.sid=socket.gethostname()
      self.message=""

      # Private members
      self._auth=DEF_AUTH
      self._chunk=4096
      self._sock=None
      self._timer=None
      self._DEBUG=False
      self._accountmanager=AccountManager(DEF_ACCOUNTDB)

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
   print (f"{C.bdr}{C.cly}CTRL-C Detected!{C.off}")
   print (f"{C.cwh}Aborting communications and exiting...{C.off} done. ")

   # This is critical in order to kill the listener and free address/port.
   if not config._sock==None:
      config._sock.close()
   if FLAG_LOGOPEN:
      logfilehandle.close()
   print ()
   exit()

# Outputs a message to a log file.
# Strips the ANSI colour codes out of the string to stop log clutter.
# Caches file handle so that it is only opened once, and closed on exit.
# Applies a header to new logging session (captured to same logfile).
# Format of a log is:
# [time since program start] message
def log(message):
   global FLAG_LOGOPEN, logfilehandle
   if not FLAG_LOGOPEN:
      logfilehandle=open(config.logfile, "at+")
      FLAG_LOGOPEN=True
      log.logtimer=Timer()
      log.logtimer.start()
      now=datetime.datetime.now()
      header=f"\n******************************************************************************\n" \
             f"FBOMB Log File for FSERVE {config.sid}@{config.host}:{config.port}\n" \
             f"On: {now:%Y-%m-%d %H:%M}\n" \
             f"******************************************************************************\n"
      logfilehandle.write(f"{header}\n")
   logmsg=f"[{log.logtimer.peek():.5f}] {C.cstrip(message)}"
   if (not logmsg.endswith("\n")):
      logmsg=logmsg+"\n"
   logfilehandle.write(f"{logmsg}")
   logfilehandle.flush()

# Outputs a message for a serious error, and terminates program
# Use this for fatal errors only!
def error(message):
   if (not FLAG_KILL):
      print(f"{C.clr}An error has occurred!");
      print(f"{C.clm}{message}{C.coff}{C.boff}")
      print(flush=True)
      try:
         if (config.islogging):
            log(message)
         if (config._sock):
            config._sock.close()
      except Exception as e:
            pass
      finally:
         exit()

# "Pips up" to let you know something minor happened, doesn't impact
# program flow. This method is intended for non-fatal errors.
def pip(message, isalert=False):
   if isalert:
      print(f"{C.cly}{C.bdr}{message}{C.off}")
   else:
      print(f"{C.clg}{C.bdg}{message}{C.off}")
   try:
      if (config.islogging):
         log(message)
   except Exception as e:
      pass

# Outputs a message to screen only if in verbose mode OR if show==true
# IE: note() -> only shown if verbose mode enabled
def note(message, show=False):
   if (config.isverbose or show==True):
      print(f"{C.clc}{C.boff}{message}{C.off}")
   # Always write to logfile no matter if verbose or not
   try:
      if (config.islogging):
         log(message)
   except Exception as e:
      pass

# Just outputs a message regardless of verboseness
# IE: notex() -> always shown
def notex(message):
   note(message, show=True)

# Adds a user and password to database.
# Note that password is salted with username.
# The default action is "add", but "delete", "list" and "update" are
# also supported.
def manageAccount(arg="null", action=ACTMGR_ACTIONS.ADD_USER):
   # Validate and sanitize
   mgr=config._accountmanager
   if (action==ACTMGR_ACTIONS.ADD_USER):
      valid, user, password=extractUP(arg)
      if (not valid):
         error(f"Wrong format '{arg}'. To add a user account with a password, use form \"user:password\"")
      passwordHash=AccountManager.saltPassword(user, password)
      if (not mgr.addUser(user, passwordHash)):
         error(f"Failed to add {user} with password {paswordHash}.")
      pip(f"New user {user} successfully added.")
   
   elif (action==ACTMGR_ACTIONS.LIST_USERS):
      data=mgr.listUsers()
      notex(f"{C.cwh}{'ID':<3}{'User':<12}" \
            f"{'Salted Password Hash (SHA256)':<65}{'Created':<10}")
      for record in data:
         notex(f"{C.clgy}{record[0]:<3}{record[1]:<12}{record[2]:<65}"\
               f"{record[3][0:10]:<10}")
   
   elif (action==ACTMGR_ACTIONS.DELETE_USER):
      if (arg=="null" or arg==""):
         error(f"Malformed user '{arg}'. Please specify valid user. " \
               f"Use --list to see all users.")
      if (mgr.deleteUser(arg)):
         pip(f"Successfully removed user {arg}.")
      else:
         error(f"User {arg} could not be deleted. May not exist. "\
               f"Use --list to see all users.")
         
   elif (action==ACTMGR_ACTIONS.UPDATE_USER):
      valid, user, password=extractUP(arg)
      if (not valid):
         error(f"Wrong format '{arg}'. To update a password, use form \"user:password\"")
      # updatePassword applies the salt and creates hash for us
      if (not mgr.updatePassword(user, password)):
         error(f"Failed to update password for user {user}.")
      pip(f"Password for {user} successfully modified.")

   return

# Receives inbound instructions as a string
def getRequest(con):
   data=con.recv(1024)
   msg=data.decode(DEF_ENC)
   note(f"{C.cly}[{config._timer.peek():.5f} RECV] {C.cwh}{msg.rstrip()}")
   return (msg)

# Transmits outbound data as bytes
def sendResponse(con, msg):
   data=msg.encode(DEF_ENC)
   con.sendall(data)
   note(f"{C.cly}[{config._timer.peek():.5f} SENT] {C.clgy}{msg.rstrip()}{C.off}")

# Handles ASCII files an os dependent line terminators.
def receiveASCII(con, fd):
   file=open(config.home+fd.filename, "w+")
   notex (f"{C.cwh}Receving ASCII file: {C.clgy}{config.home+fd.filename}")
   bytes=0
   while True:
      data=con.recv(config._chunk)
      if not data:
         break
      file.write(data.decode(DEF_ENC))
      bytes+=len(data)
      progress=int((bytes/fd.length)*100)
      print(f"{C.cly}Progress: {C.cwh}{progress:4}%", end='\r', flush="True")
      if (bytes==fd.length):
         break
   file.close()
   note (f"{C.clc}Received {C.clr}ASCII{C.clc} file " \
         f"{C.cwh}{config.home+fd.filename} " \
         f"{C.cwh}({C.clgy}{bytes:,} {C.cwh}bytes) {C.clc}in " \
         f"{C.clg}{config._timer.peek():.5f} {C.clc}seconds.")
   return

# Computes and compares hash values.
def isValidHash(fd):
   h=hashlib.new(fd.hashtype.lower())
   with open(config.home+fd.filename, "rb") as file:
      h.update(file.read())
      digest=h.hexdigest()
   return (digest==fd.hash)

# Receives binary data
def receiveBinary(con, fd):
   bytes=0
   file=open(config.home+fd.filename, "wb+")
   notex (f"{C.cwh}Receving binary file: {C.clgy}{config.home+fd.filename}")
   while True:
      data=con.recv(config._chunk)
      if not data:
         break
      bytes+=len(data)
      file.write(data)
      progress=int((bytes/fd.length)*100)
      print(f"{C.cly}Progress: {C.cwh}{progress:4}%", end='\r', flush="True")
      if (bytes==fd.length):
         break
   file.close()
   print()
   note (f"{C.clc}Received {C.clr}BINARY{C.clc} file {C.cwh}{config.home+fd.filename} " \
         f"{C.cwh}({C.clgy}{bytes:,} {C.cwh}bytes) {C.clc}in " \
         f"{C.clg}{config._timer.peek():.5f} {C.clc}seconds.")
   if isValidHash(fd):
      pip (f"Hash is valid: {isValidHash(fd)}")
   else:
      pip (f"Warning! File hash codes do NOT match!", isalert=True)

# OS indepedently strips path returning filename
def strippath(path):
   head, tail = ntpath.split(path)
   return tail or ntpath.basename(head)

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
   s=re.sub("(?i)hi","",s).strip()

   if (s.startswith(":") or s.endswith(":")):
       return (False, user, password)

   ss=s.split(":")
   if (len(ss)<2):
      return (False, user, password)

   user=ss[0]
   password=ss[1]
   return(True, user, password)
   

# Handles the protocol
# TODO: Convert from linear to state machine
def stateMachine(con, addr):
   # Start FBOMB protocol communication
   result=False
   request=getRequest(con)
   if (request.upper().startswith("HI ")):
      if (config._auth):
         # Authentication mode. Retrieve user+pwd (user:pwd)
         valid,user,password=extractUP(request)
         if valid:
            pip(f"Login request from {user}:{password}")
            result=config._accountmanager.verifyPassword(user, password)
            if (result):
               pip(f"Login approved for {user}@{addr[0]}:{addr[1]} " \
                   f"on {str(datetime.datetime.now())[0:-10]}")
            else:
               pip(f"Login denied for {user}@{addr[0]}:{addr[1]} " \
                   f"on {str(datetime.datetime.now())[0:-10]}", isalert=True)
         else:
            pip(f"Malformed user:pwd provided: {user}:{password}",
                isalert=True)
            result=False

         if (not result):
            response = f"NOK Bad user:pwd"
            sendResponse(con, response)
            con.close()
            return

      # No authentication or was authenticated
      response = f"OK {config.sid}"
      if (not config.message==''):
         response+=f" | {config.message}"
      sendResponse(con, response)

      request=getRequest(con)
      note ("Inbound File Descriptor info:")
      fd = FileDescriptor.deserialize (request)
      fd.filename=strippath(fd.filename)
      note (f"{C.clgy}{fd.toString()}")

      if (os.path.exists(config.home+fd.filename) and not config.isoverwrite):
         reason = "File already exists; overwrite is turned off."
         sendResponse(con, f"NOK | {reason}")
         error(reason)
      elif (not isSafeFilename(config.home+fd.filename)):
         reason = "Filename is not a valid name on server OS."
         sendResponse(con, f"NOK | {reason}")
         error(reason)
      else:
         sendResponse(con, "OK Proceed")
         if (fd.filemode==FILEMODE.ASCII):
            receiveASCII(con, fd)
         else:
            receiveBinary(con, fd)

      sendResponse(con, "OK Received | Issue BYE to terminate")
      msg=getRequest(con)
      con.close()

# From:
# https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta/9532586
def isSafeFilename(pathname: str) -> bool:
    '''
    `True` if the passed pathname is a valid pathname for the current OS;
    `False` otherwise.
    '''
    # If this pathname is either not a string or is but is empty, this pathname
    # is invalid.
    try:
        if not isinstance(pathname, str) or not pathname:
            return False

        # Strip this pathname's Windows-specific drive specifier (e.g., `C:\`)
        # if any. Since Windows prohibits path components from containing `:`
        # characters, failing to strip this `:`-suffixed prefix would
        # erroneously invalidate all valid absolute Windows pathnames.
        _, pathname = os.path.splitdrive(pathname)

        # Directory guaranteed to exist. If the current OS is Windows, this is
        # the drive to which Windows was installed (e.g., the "%HOMEDRIVE%"
        # environment variable); else, the typical root directory.
        root_dirname = os.environ.get('HOMEDRIVE', 'C:') \
            if sys.platform == 'win32' else os.path.sep
        assert os.path.isdir(root_dirname)  

        # Append a path separator to this directory if needed.
        root_dirname = root_dirname.rstrip(os.path.sep) + os.path.sep

        # Test whether each path component split from this pathname is valid or
        # not, ignoring non-existent and non-readable path components.
        for pathname_part in pathname.split(os.path.sep):
            try:
                os.lstat(root_dirname + pathname_part)
            # If an OS-specific exception is raised, its error code
            # indicates whether this pathname is valid or not. Unless this
            # is the case, this exception implies an ignorable kernel or
            # filesystem complaint (e.g., path not found or inaccessible).
            #
            # Only the following exceptions indicate invalid pathnames:
            #
            # * Instances of the Windows-specific "WindowsError" class
            #   defining the "winerror" attribute whose value is
            #   "ERROR_INVALID_NAME". Under Windows, "winerror" is more
            #   fine-grained and hence useful than the generic "errno"
            #   attribute. When a too-long pathname is passed, for example,
            #   "errno" is "ENOENT" (i.e., no such file or directory) rather
            #   than "ENAMETOOLONG" (i.e., file name too long).
            # * Instances of the cross-platform "OSError" class defining the
            #   generic "errno" attribute whose value is either:
            #   * Under most POSIX-compatible OSes, "ENAMETOOLONG".
            #   * Under some edge-case OSes (e.g., SunOS, *BSD), "ERANGE".
            except OSError as exc:
                if hasattr(exc, 'winerror'):
                    if exc.winerror == ERROR_INVALID_NAME:
                        return False
                elif exc.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                    return False
    # If a "TypeError" exception was raised, it almost certainly has the
    # error message "embedded NUL character" indicating an invalid pathname.
    except TypeError as exc:
        return False
    # If no exception was raised, all path components and hence this
    # pathname itself are valid.
    else:
        return True

# Shows the info, blurb, syntax and options screen.
def showHelp():
   #This header line is now always printed at start of program.
   #print (f"{C.cly}{C.bdb}{APP_NAME}{C.boff} v{APP_VERSION} by {APP_AUTHOR} {APP_DATE} {APP_EMAIL}")
   print (f"{APP_BLURB}")
   print ()
   print (f"{C.clg}{APP_SYNTAX}");
   print ()
   print (f"{C.clc}Arguments")
   print (f"{C.clg}-a, --adduser:        {C.clc}Adds user account    [{C.clm}user:password{C.clc}]")
   print (f"{C.clg}-d, --deleteuser:     {C.clc}Deletes user account [{C.clm}user{C.clc}]")
   print (f"{C.clg}-u, --updatepassword: {C.clc}Change user password [{C.clm}user:password{C.clc}]")
   print (f"{C.clg}-s, --sid:            {C.clc}Set server ID        ({C.clm}default{C.clc} is {C.cwh}{socket.gethostname()}{C.clc})")
   print (f"{C.clg}-m, --message:        {C.clc}Sets optional message to be sent to client on connection")
   print (f"{C.clg}-h, --host:           {C.clc}Address to bind to   ({C.clm}default{C.clc} is {C.cwh}localhost{C.clc})")
   print (f"{C.clg}-p, --port:           {C.clc}Port to listen on    ({C.clm}default{C.clc} is {C.cwh}33333)")
   print (f"{C.clg}-l, --log:            {C.clc}Enables logging and specifies log file; use -l \"\" for default")
   print (f"                      ({C.clm}default{C.clc} log file is {C.cwh}{DEF_LOGFILE})")
   print (f"{C.clgy}Parameter values can be after '=' or a space (ie, -p 10000 or -p=10000)")
   print ()
   print (f"{C.clc}Switches")
   print (f"{C.clg}-?, --help:      {C.clc}This help screen")
   print (f"{C.clg}-x, --noauth:    {C.clc}Turns user authentication off. Use with caution.")
   print (f"{C.clg}-t, --list:      {C.clc}List all users and exit")
   print (f"{C.clg}-v, --verbose:   {C.clc}Enable verbose mode")
   print (f"{C.clg}-o, --overwrite: {C.clc}Enables overwriting existing files")
   print (f"{C.clg}--version:       {C.clc}Reports program version number and exits")
   print (f"{C.coff}")
   exit()

# Parses options, switches and args.  Does validation.  Populates the config
# structure which contains the info need to do the file transfer.
def parseCommandLine():
   if argc<2:
      showHelp()

   # We store retrieved arguments ins a config structure
   config=Config()

   # Single switch options are listed with a ":" suffix only if they expect a value.
   # Extended options (--) must have a "=" suffix if value is expected
   try:
       opts, args =getopt.getopt(argv[1:],
        "?SvDotxa:d:h:p:m:s:l:u:",
        ["help","version","verbose", "overwrite", "DEBUG", "list",
         "deleteuser=", "adduser=", "host=","port=", "message=",
         "sid=", "log=", "noauth", "updatepassword=", "update="])
   except getopt.GetoptError as e:
      error(f"Arguments error: {e.msg} {e.opt}")
      showHelp()

   # Process
   for opt, arg in opts:
      #This line is useful for option debugging:
      #print(f"OPT:{opt}  ARG:{arg}")

      if (opt in ("-?", "--help")):
         showHelp()

      # This option check must come before version check
      # as "-v" is in version, and I'm sticking to the "in" patern
      # (it makes expansion easy)
      elif (opt in("-v", "--verbose")):
         config.isverbose=True

      # If file already exists, allows replacement
      elif (opt in("-o", "--overwrite")):
         config.isoverwrite=True

      # Handle logging as either a switch or an argument
      elif (opt in("-l", "--log")):
         config.islogging=True
         if (not arg==""):
            if (isSafeFilename(arg)):
               config.logfile=arg
         else:
            config.logfile=DEF_LOGFILE

      # Debugging flag
      elif (opt in ("-D", "--DEBUG")):
         config._DEBUG=True

      # Turn on/off authentication (login)
      elif (opt in ("-x", "--noauth")):
         config._auth=False

      # Show version and then exit immediately
      elif (opt in ("--version")):
         print(f"{C.clc}Version: {C.clg}{APP_VERSION}{C.off}")
         exit()

      # Add a user then exit
      elif (opt in ("-a", "--adduser")):
         manageAccount(arg, ACTMGR_ACTIONS.ADD_USER)
         exit()

      elif (opt in ("-t", "--list")):
         manageAccount(action=ACTMGR_ACTIONS.LIST_USERS)
         exit()

      elif (opt in ("-d", "--deleteuser")):
         manageAccount(arg, action=ACTMGR_ACTIONS.DELETE_USER)
         exit()

      elif (opt in ("-u", "--update", "--updatepassword")):
         manageAccount(arg, action=ACTMGR_ACTIONS.UPDATE_USER)
         exit()

      # Optional message for response to "HI" request
      elif (opt in ("-m", "--message")):
         config.message=arg.strip()

      # Sets server host.  Can be a resolvable name, or IP address
      elif (opt in ("-h", "--host")):
         config.host=arg

      # Sets server port to connect to.
      elif (opt in ("-p", "--port")):
         config.port=int(arg)

      # Sets the client ID; default is hostname
      elif (opt in ("-s", "--sid")):
         config.sid=arg.strip()

      # Greetings are always welcome
      elif (opt in ("-S")):
         pip(f"{C.bdr}{C.cly}Sultaneous sends salutations.{C.off}")
         exit()

   # The first argument should be the home directory; 
   # decorate with OS specific path separator if necessary
   for arg in args:
      if not arg=="":
         config.home=arg
         if not config.home.endswith(os.path.sep):
            config.home+=os.path.sep
      break

   return(config)


def main():
   # Register signal handler
   signal.signal(signal.SIGINT, onSignal_kill)

   global config
   config=Config()
   
   print (f"{C.cly}{C.bdb}{APP_NAME}{C.boff} v{APP_VERSION} by {APP_AUTHOR} {APP_DATE} {APP_EMAIL}{C.off}")
   config=parseCommandLine()

   if (config._DEBUG):
      notex (config.toString(showprivate=True))
      exit()

   # Inbound directory must exist
   if not os.path.isdir(config.home):
      error("Invalid home (inbound) directory: "+config.home)

   note(f"{C.clg}{C.bdg}Verbose Mode{C.boff}{C.clc} is on. Outputting details.")

   if (config.isoverwrite):
      note(f"{C.clg}{C.bdg}Overwrite Mode{C.boff}{C.clc} is on. Existing files can be replaced.")

   if (config.islogging):
      note(f"{C.clg}{C.bdg}Logging Mode{C.boff}{C.clc} is on. Logging to {C.clg}{config.logfile}{C.clc}.")

   note(f"{C.clc}Outputting client configuration:")
   note(f"{C.clgy}{config.toString()}{C.coff}")

   try:
      sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      config._sock=sock
      note(f"Attempting to bind to {config.host}:{config.port}")
      sock.bind((config.host, config.port))
      notex (f"{C.clc}Listening on {C.cly}{config.host}:{C.clg}{config.port}")
      notex (f"{C.clr}Press {C.bdr}CTRL-C{C.boff} to quit...")
      uptime=Timer()
      uptime.start()
   except socket.error as e:
      error(f"Network error occurred: {e}")

   connections=0
   while True:
      try:
         sock.listen()
         con,addr = sock.accept()
         config._timer=Timer()
         config._timer.start()
         connections+=1
         notex(f"{C.clg}{C.bdg}Connection from:{C.boff} {addr}")

         stateMachine(con,addr)

         config._timer.stop()
         pip (f"Listening... Handled {connections} connections so far.")

         # Flush any pending logs to the file
         if FLAG_LOGOPEN:
            logfilehandle.flush()
      except socket.error as e:
         error(f"Network error occurred: {e}")

   sock.close()
   uptime.stop()
   print (f"{C.off}Server shutdown complete.  Uptime: {uptime.elapsed():.5f} seconds")


# Run program
if __name__ == "__main__":
   main()
