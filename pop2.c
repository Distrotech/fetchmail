/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       pop2.c
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
		Hacks and bug fixes by esr.
  description:  POP2 client code.

 ***********************************************************************/

#include  <config.h>

#include  <stdio.h>
#if defined(STDC_HEADERS)
#include  <string.h>
#endif
#if defined(HAVE_UNISTD_H)
#include  <unistd.h>
#endif

#include  <sys/time.h>
#include  <errno.h>

#include  "socket.h"
#include  "fetchmail.h"


/* TCP port number for POP2 as defined by RFC 937 */
#define	  POP2_PORT	109

#if HAVE_PROTOTYPES
/* prototypes for internal functions */
int POP2_sendcmd (char *cmd, int socket);
int POP2_sendHELO (char *userid, char *password, int socket);
int POP2_sendFOLD (char *folder, int socket);
int POP2_quit (int socket);
int POP2_stateGREET (int socket);
int POP2_stateNMBR (int socket);
int POP2_stateSIZE (int socket);
int POP2_stateXFER (int msgsize, int socket, int mboxfd, int topipe);
#endif


/*********************************************************************
  function:      doPOP2
  description:   retrieve messages from the specified mail server
                 using Post Office Protocol 2.

  arguments:     
    queryctl     fully-specified options (i.e. parsed, defaults invoked,
                 etc).

  return value:  exit code from the set of PS_.* constants defined in 
                 fetchmail.h
  calls:         POP2_stateGREET, POP2_stateNMBR, POP2_stateSIZE,
                 POP2_stateXFER, POP2_sendcmd, POP2_sendHELO,
                 POP2_sendFOLD, POP2_quit, Socket, openuserfolder,
                 closeuserfolder, openmailpipe, closemailpipe.
  globals:       reads outlevel.
 *********************************************************************/

int doPOP2 (queryctl)
struct hostrec *queryctl;
{
  int mboxfd;
  int socket;
  int number,msgsize,actsize;
  int status = PS_UNDEFINED;

  /* check for unsupported options */
  if (linelimit) {
    fprintf(stderr,"Option --limit is not supported with POP2\n");
    return(PS_SYNTAX);
  }
  else if (queryctl->flush) {
    fprintf(stderr,"Option --flush is not supported with POP2\n");
    return(PS_SYNTAX);
  }
  else if (queryctl->fetchall) {
    fprintf(stderr,"Option --all is not supported with POP2\n");
    return(PS_SYNTAX);
  }
  else if (queryctl->smtphost[0]) {
    fprintf(stderr,"Option --smtphost is not supported with POP2\n");
    return(PS_SYNTAX);
  }
  else
    ;

  /* open the socket to the POP server */
  if ((socket = Socket(queryctl->servername,
		     queryctl->port ? queryctl->port : POP2_PORT)) < 0)
  {
    perror("doPOP2: socket");
    return(PS_SOCKET);
  }
    
  /* open/lock the folder if it is a user folder or stdout */
  if (queryctl->output == TO_FOLDER)
    if ((mboxfd = openuserfolder(queryctl)) < 0) 
      return(PS_IOERR);
 
  /* wait for the POP2 greeting */
  if (POP2_stateGREET(socket) != 0) {
    POP2_quit(socket);
    status = PS_PROTOCOL;
    goto closeUp;
  }

  /* log the user onto the server */
  POP2_sendHELO(queryctl->remotename,queryctl->password,socket);
  if ((number = POP2_stateNMBR(socket)) < 0) {
    POP2_quit(socket);
    status = PS_AUTHFAIL;
    goto closeUp;
  }

  /* set the remote folder if selected */
  if (*queryctl->remotefolder != 0) {
    POP2_sendFOLD(queryctl->remotefolder,socket);
    if ((number = POP2_stateNMBR(socket)) < 0) {
      POP2_quit(socket);
      status = PS_PROTOCOL;
      goto closeUp;
    }
  }

  /* tell 'em how many messages are waiting */
  if (outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%d messages in folder %s\n",number,queryctl->remotefolder);
  else
    ;

  /* fall into a retrieve/acknowledge loop */
  if (number > 0) { 

    POP2_sendcmd("READ",socket);
    msgsize = POP2_stateSIZE(socket);
    while (msgsize > 0) {

      /* open the pipe */
      if (queryctl->output == TO_MDA)
        if ((mboxfd = openmailpipe(queryctl)) < 0) {   
          POP2_quit(socket);
          return(PS_IOERR);
        }

      POP2_sendcmd("RETR",socket);
      actsize = POP2_stateXFER(msgsize,socket,mboxfd,
                               queryctl->output == TO_MDA);
      if (actsize == msgsize) 
        if (queryctl->keep)
          POP2_sendcmd("ACKS",socket);
        else
          POP2_sendcmd("ACKD",socket);
      else if (actsize >= 0) 
        POP2_sendcmd("NACK",socket);
      else {
        POP2_quit(socket);
	status = PS_SOCKET;
	goto closeUp; 
      }

      /* close the pipe */
      if (queryctl->output == TO_MDA)
        if (closemailpipe(mboxfd) < 0) {
          POP2_quit(socket);
          status = PS_IOERR;
	  goto closeUp;
        }
    
      msgsize = POP2_stateSIZE(socket);
    }
    POP2_quit(socket);
    status = msgsize == 0 ? PS_SUCCESS : PS_PROTOCOL;
  }
  else {
    POP2_quit(socket);
    status = PS_NOMAIL;
  }

closeUp:
  if (queryctl->output == TO_FOLDER)
    closeuserfolder(mboxfd);

  return(status);
}



/*********************************************************************
  function:      POP2_sendcmd
  description:   send a command string (with no arguments) a server.
  arguments:     
    cmd          command string to send.
    socket       socket to which the server is connected.

  return value:  none.
  calls:         SockPuts.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_sendcmd (cmd,socket) 
char *cmd;
int socket;
{
  SockPuts(socket,cmd);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s\n",cmd);
  else
    ;
}


/*********************************************************************
  function:      POP2_sendHELO
  description:   send the HELO command to the server.
  arguments:     
    userid       user's mailserver id.
    password     user's mailserver password.
    socket       socket to which the server is connected.

  return value:  none.
  calls:         SockPrintf.
  globals:       read outlevel.
 *********************************************************************/

int POP2_sendHELO (userid,password,socket) 
char *userid, *password;
int socket;
{
  SockPrintf(socket,"HELO %s %s\r\n",userid,password);
    

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> HELO %s password\n",userid);
  else
    ;
}


/*********************************************************************
  function:      POP2_sendFOLD
  description:   send the FOLD command to the server.
  arguments:     
    folder       name of the folder to open on the server.
    socket       socket to which the server is connected.  

  return value:  none.
  calls:         SockPrintf.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_sendFOLD (folder,socket)
char *folder;
int socket;
{
  SockPrintf(socket,"FOLD %s\r\n",folder);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> FOLD %s\n",folder);
  else
    ;
}


/*********************************************************************
  function:      POP2_quit
  description:   send the QUIT command to the server and close 
                 the socket.

  arguments:     
    socket       socket to which the server is connected.

  return value:  none.
  calls:         SockPuts.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_quit (socket)
int socket;
{
  SockPuts(socket,"QUIT");
  close(socket);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> QUIT\n");
  else
    ;
}


/*********************************************************************
  function:      POP2_stateGREET
  description:   process the GREET state as described in RFC 937.
  arguments:     
    socket       ...to which server is connected.

  return value:  zero if server's handling of the GREET state was 
                 correct, else non-zero (may indicate difficulty
                 at the socket).
  calls:         SockGets.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_stateGREET (socket)
int socket;
{
  char buf [POPBUFSIZE+1];
 
  /* read the greeting from the server */
  if (SockGets(socket, buf, sizeof(buf)) >= 0) {

    /* echo the server's greeting to the user */
    if (outlevel > O_SILENT)
      fprintf(stderr,"POP2 greeting: %s\n",buf);
    else
      ;
    /* is the greeting in the correct format? */
    if (*buf == '+')
      return(0);
    else
      return(-1);
  }
  else {
    /* an error at the socket */ 
    if (outlevel > O_SILENT)
      perror("error reading socket\n");
    else
      ;
    return(-1);
  }
}


/*********************************************************************
  function:      POP2_stateNMBR
  description:   process the NMBR state as described in RFC 937.
  arguments:     
    socket       ...to which the server is connected.

  return value:  zero if the expected NMBR state action occured, else
                 non-zero.  Following HELO, a non-zero return value 
                 usually here means the user authorization at the server
                 failed.
  calls:         SockGets.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_stateNMBR (socket)
int socket;
{
  int number;
  char buf [POPBUFSIZE+1];

  /* read the NMBR (#ccc) message from the server */
  if (SockGets(socket, buf, sizeof(buf)) >= 0) {

    /* is the message in the proper format? */
    if (*buf == '#') {
      number = atoi(buf + 1);
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"%s\n",buf);
      else
        ;
    }
    else {
      number = -1;
      if (outlevel > O_SILENT) 
        fprintf(stderr,"%s\n",buf);
      else
        ;
    }
  }
  else {
    /* socket problem */
    number = -1;
    if (outlevel == O_VERBOSE) 
      perror("socket read error\n");
    else
      ;
  }
  return(number);
}


/*********************************************************************
  function:      POP2_stateSIZE
  description:   process the SIZE state as described in RFC 937.
  arguments:     
    socket       ...to which the server is connected.

  return value:  zero if the expected SIZE state action occured, else
                 non-zero (usually indicates a protocol violation).
  calls:         SockGets.
  globals:       reads outlevel.
 *********************************************************************/

int POP2_stateSIZE (socket)
int socket;
{
  int msgsize;
  char buf [POPBUFSIZE+1];

  /* read the SIZE message (=ccc) from the server */
  if (SockGets(socket, buf, sizeof(buf)) >= 0) 
    /* is the message in the correct format? */
    if (*buf == '=') {
      msgsize = atoi(buf + 1);
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"%s\n",buf);
      else
        ;
    }
    else {
      msgsize = -1;
      if (outlevel > O_SILENT) 
        fprintf(stderr,"%s\n",buf);
      else
        ;
    }
  else {
    /* socket problem */
    msgsize = -1;
    if (outlevel == O_VERBOSE) 
      perror("socket read error\n");
    else
      ;
  }

  return(msgsize);
}


/*********************************************************************
  function:      POP2_stateXFER
  description:   process the XFER state as described in RFC 937.
  arguments:     
    msgsize      content length of the message as reported in the 
                 SIZE state.
    socket       ... to which the server is connected.
    mboxfd       open file descriptor to which the retrieved message will
                 be written.  
    topipe       true if we're writing to a the /bin/mail pipe.

  return value:  
    >= 0         actual length of the message received. 
    < 0          socket I/O problem.

  calls:         SockRead.
  globals:       reads outlevel. 
 *********************************************************************/

int POP2_stateXFER (msgsize,socket,mboxfd,topipe)
int msgsize;
int socket;
int mboxfd;
int topipe;
{
  int i,buflen,actsize;
  char buf [MSGBUFSIZE+1]; 
  char frombuf [MSGBUFSIZE+1];
  char savec;
  int msgTop;
  int needFrom;
  
  time_t now;

  /* This keeps the retrieved message count for display purposes */
  static int msgnum = 0;  

  /* set up for status message if outlevel allows it */
  if (outlevel > O_SILENT && outlevel < O_VERBOSE) {
    fprintf(stderr,"reading message %d",++msgnum);
    /* won't do the '...' if retrieved messages are being sent to stdout */
    if (mboxfd == 1)  /* we're writing to stdout */
      fputs(".\n",stderr);
    else
      ;
  }
  else
    ;


  /* read the specified message content length from the server */
  actsize = 0;
  msgTop = !0;
  while (msgsize > 0) {
    buflen = msgsize <= MSGBUFSIZE ? msgsize : MSGBUFSIZE;
    /* read a bufferful */ 
    if (SockRead(socket, buf, buflen) == 0) {

      /* Check for Unix 'From' header, and add bogus one if it's not
         present -- only if not using an MDA.
         XXX -- should probably parse real From: header and use its
                address field instead of bogus 'POPmail' string.
      */
      if (!topipe && msgTop) {
        msgTop = 0;
        if (strlen(buf) >= strlen("From ")) {
          savec = *(buf + 5);
          *(buf + 5) = 0;
          needFrom = strcmp(buf,"From ") != 0;
          *(buf + 5) = savec;
        }
        else
          needFrom = 1;
        if (needFrom) {
          now = time(NULL);
          sprintf(frombuf,"From POPmail %s",ctime(&now));
          if (write(mboxfd,frombuf,strlen(frombuf)) < 0) {
            perror("POP2_stateXFER: write");
            return(-1);
          }
        }
      }

      /* write to folder, stripping CR chars in the process */
      for (i = 0;  i < buflen;  i++)
        if (*(buf + i) != '\r')
          if (write(mboxfd,buf + i,1) < 0) {
            perror("POP2_stateXFER: write");
            return(-1);
          }
          else
            ;  /* it was written */
        else
          ;  /* ignore CR character */
    }
    else
      return(-1);   /* socket problem */

    /* write another . for every bufferful received */
    if (outlevel > O_SILENT && outlevel < O_VERBOSE && mboxfd != 1) 
      fputc('.',stderr);
    else
      ;
    msgsize -= buflen;
    actsize += buflen;
  }

  if (!topipe) {
    /* The server may not write the extra newline required by the Unix
       mail folder format, so we write one here just in case */
    if (write(mboxfd,"\n",1) < 1) {
      perror("POP2_stateXFER: write");
      return(-1);
    }
  }
  else {
     /* the mailer might require some sort of termination string, send
        it if it is defined */
#ifdef BINMAIL_TERM
    if (write(mboxfd,BINMAIL_TERM,strlen(BINMAIL_TERM)) < 0) {
      perror("POP2_stateXFER: write");
      return(-1);
    }
#endif
  }

  /* finish up display output */
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"(%d characters of message content)\n",actsize);
  else if (outlevel > O_SILENT && mboxfd != 0)
    fputc('\n',stderr);
  else
    ;

  return(actsize);
}
