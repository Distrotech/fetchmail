#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "fetchmail.h"

 
int is_ip_alias(const char *name1,const char *name2)
/* Given two hostnames as arguments, returns TRUE if they
 * have at least one IP address in common.
 * It is meant to be called by the is_host_alias() function in driver.c
 * No check is done on errors returned by gethostbyname,
 * the calling function does them.
 */
     {

	typedef unsigned char address_t[sizeof (struct in_addr)]; 
	typedef struct _address_e { struct _address_e *next;
			address_t address;
			} address_e;

	address_e *host_a_addr, *host_b_addr,*dummy_addr;
	
	int i;

        struct hostent *hp;

        char **p;
 
         hp = gethostbyname(name1);
 
	 dummy_addr = (address_e *)NULL;

         for (i=0,p = hp->h_addr_list; *p != 0; i++,p++) {
	        struct in_addr in;
		(void) memcpy(&in.s_addr, *p, sizeof (in.s_addr));
		host_a_addr = (address_e *)xmalloc(sizeof( address_e));
		memset (host_a_addr,0, sizeof (address_e));
		host_a_addr->next = dummy_addr;
		(void) memcpy(&host_a_addr->address, *p, sizeof (in.s_addr));
		dummy_addr = host_a_addr;
         }


         hp = gethostbyname(name2);

	 dummy_addr = (address_e *)NULL;

         for (i=0,p = hp->h_addr_list; *p != 0; i++,p++) {
		struct in_addr in;
		(void) memcpy(&in.s_addr, *p, sizeof (in.s_addr));
		host_b_addr = (address_e *)xmalloc(sizeof( address_e));
		memset (host_b_addr,0, sizeof (address_e));
		host_b_addr->next = dummy_addr;
		(void) memcpy(&host_b_addr->address, *p, sizeof (in.s_addr));
		dummy_addr = host_b_addr;
         }

	while (host_a_addr) {
				while (host_b_addr) {

                                if (!memcmp(host_b_addr->address,host_a_addr->address, sizeof (address_t))) return (TRUE);

				host_b_addr = host_b_addr->next;
				}
				host_a_addr = host_a_addr->next;
	}
return (FALSE);
}

