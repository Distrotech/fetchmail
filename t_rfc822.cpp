#include "fetchmail.h"
#include <unistd.h>
#include <strings.h>

using namespace std;

int testmode = 0;
int outlevel = O_DEBUG;
const char *program_name;

static void parsebuf(char *longbuf, int reply)
{
    char	*cp;
    size_t	dummy;

    if (reply)
    {
	reply_hack(longbuf, "HOSTNAME.NET", &dummy);
	printf("Rewritten buffer: %s", (char *)longbuf);
    }
    else
	if ((cp = nxtaddr(longbuf)) != (char *)NULL)
	    do {
		printf("\t-> \"%s\"\n", (char *)cp);
	    } while
		((cp = nxtaddr((char *)NULL)) != (char *)NULL);
}



int main(int argc, char *argv[])
{
    char	buf[BUFSIZ], longbuf[BUFSIZ];
    int		ch, reply;
    bool	verbose;

    program_name = "rfc822";
    verbose = reply = false;
    while ((ch = getopt(argc, argv, "rv")) != EOF)
	switch(ch)
	{
	case 'r':
	    reply = true;
	    break;

	case 'v':
	    verbose = true;
	    break;
	}

    longbuf[0] = '\0';
    testmode = verbose ? 1 : 0;

    while (fgets(buf, sizeof(buf)-1, stdin))
    {
	if (buf[0] == ' ' || buf[0] == '\t')
	    strlcat(longbuf, buf, sizeof(longbuf));
	else if (!strncasecmp("From: ", buf, 6)
		    || !strncasecmp("To: ", buf, 4)
		    || !strncasecmp("Reply-", buf, 6)
		    || !strncasecmp("Cc: ", buf, 4)
		    || !strncasecmp("Bcc: ", buf, 5))
	    strlcpy(longbuf, buf, sizeof(longbuf));
	else if (longbuf[0])
	{
	    if (verbose)
		fputs(longbuf, stdout);
	    parsebuf(longbuf, reply);
	    longbuf[0] = '\0';
	}
    }

    if (longbuf[0])
    {
	if (verbose)
	    fputs(longbuf, stdout);
	parsebuf(longbuf, reply);
    }

    return 0;
}
