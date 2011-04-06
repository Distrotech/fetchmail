#include "fetchmail.h"
#include "netrc.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdio>

using namespace std;

const char *program_name;

int main (int argc, char **argv)
{
    struct stat sb;
    char *file, *host, *login;
    netrc_entry *head, *a;

    program_name = argv[0];
    file = argv[1];
    host = argv[2];
    login = argv[3];

    switch (argc) {
	case 2:
	case 4:
	    break;
	default:
	    fprintf (stderr, "Usage: %s <file> [<host> <login>]\n", argv[0]);
	    exit(EXIT_FAILURE);
    }

    if (stat (file, &sb))
    {
	fprintf (stderr, "%s: cannot stat %s: %s\n", argv[0], file,
		 strerror (errno));
	exit (1);
    }

    head = parse_netrc (file);
    if (!head)
    {
	fprintf (stderr, "%s: no entries found in %s\n", argv[0], file);
	exit (1);
    }

    if (host && login)
    {
	int status;
	status = EXIT_SUCCESS;

	printf("Host: %s, Login: %s\n", host, login);
	    
	a = search_netrc (head, host, login);
	if (a)
	{
	    /* Print out the password (if any). */
	    if (a->password)
	    {
		printf("Password: %s\n", a->password);
	    }
	} else
	    status = EXIT_FAILURE;
	fputc ('\n', stdout);

	exit (status);
    }

    /* Print out the entire contents of the netrc. */
    a = head;
    while (a)
    {
	/* Print the host name. */
	if (a->host)
	    fputs (a->host, stdout);
	else
	    fputs ("DEFAULT", stdout);

	fputc (' ', stdout);

	/* Print the login name. */
	fputs (a->login, stdout);

	if (a->password)
	{
	    /* Print the password, if there is any. */
	    fputc (' ', stdout);
	    fputs (a->password, stdout);
	}

	fputc ('\n', stdout);
	a = a->next;
    }

    free_netrc(head);

    exit (0);
}
