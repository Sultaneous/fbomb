## About
  **fbomb** is a file transfer protocol (client(s) to server), with two utility programs to perform file transfers
across the Internet.  It's a form of *FTP* that is quick and easy to use.  Because it's cross platforn, it provides a way of
transferring files across machines, i.e. from Apple to PC to any flavour of Unix.
## Syntax
You will need to run the server **[fserve.py]** first.  Then use
the client program **[fsend]** to connect to it.

##  <a name="server">Server Utility syntax:</a>

**fserve v1.0** by Karim Sultan September 2020 karimsultan@hotmail.com   
Server program for file transfer using FBOMB protocol.
Non-threaded version; blocking, uses connection queueing.

**Syntax:** fserve [options] <inbound directory>  

***Arguments***  
**-a, --adduser:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Adds user account&nbsp;&nbsp;&nbsp;&nbsp;*[user:password]*  
**-d, --deleteuser:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Deletes user account *[user]*  
**-u, --updatepassword:**&nbsp;Change user password *[user:password]*  
**-s, --sid:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Set server ID        (default is *Kronos*)  
**-m, --message:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Sets optional message to be sent to client on connection  
**-h, --host:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Address to bind to   (default is *localhost*)  
**-p, --port:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Port to listen on    (default is *33333*)  
**-l, --log:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enables logging and specifies log file; use *-l ""* for default 
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(default log file is *fbomb.log*)  
Parameter values can be after '=' or a space (ie, -p 10000 or -p=10000)  

***Switches***  
**-?, --help:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This help screen  
**-x, --noauth:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Turns user authentication off. Use with caution.  
**-t, --list:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;List all users and exit  
**-v, --verbose:**&nbsp;&nbsp;&nbsp;&nbsp;Enable verbose mode  
**-o, --overwrite:**&nbsp;Enables overwriting existing files  
**--version:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Reports program version number and exits  

## Client Utility Syntax:[]{#client}

**fsend v1.0** by Karim Sultan September 2020 karimsultan@hotmail.com  
Client CLI program for file transfer using FBOMB protocol.

**Syntax:** fsend [options] <file1> `[<file2> ... <fileN>`]

Where:  
**-?, --help:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This help screen  
**-v, --verbose:**&nbsp;Enable verbose mode  
**-h, --host:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Target server&nbsp;&nbsp;(default is *localhost*)  
**-p, --port:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Target port&nbsp;&nbsp;&nbsp;&nbsp;(default is *33333*)  
**-m, --mode:**&nbsp;&nbsp;&nbsp;&nbsp;ASCII | BINARY&nbsp;(default is *BINARY*)  
**-c, --cid:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Set client ID&nbsp;&nbsp;(default is *Kronos*)  
**-u, --user:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Authenticate&nbsp;&nbsp;&nbsp;(syntax is *user:password*)  
 **--version:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Reports program version number and exits  
*NOTE:* Filename must be provided as an argument  
Parameter values can be after '=' or a space (ie, -p 10000 or -p=10000)

##Examples  
For example, a basic setup, using the */pub* directory, and with logging enabled,
would be:  

>
> ***python* fserve.py --noauth --verbose -l "" /pub**  
>

  This wouls start a server without authentication, allowing
anyone to connect.  To add authentication requirements for a
user **Bob** with a password of **slob**, use:  

>
> ***python* fserve.py --adduser=bob:slob**  
>

Then to connect with the client and send memo.txt, use:  

>
> ***python* fsend.py --verbose --cid=USER1 --user=bob:slob memo.txt**  
>

Although authentication protects from anonymous logins,
it does **not** secure the connection.  Usernames and
passwords are stored in a local database and are **not** encrypted.

Files are transferred at the maximum network speed. Multiple files can be 
specified on the command line, or wildcards can be used.

The server can be shutdown with **CTRL-C**.  It does not use handler threads but it does use blocking IO and queues
multiple connections to simulate a threaded application.
