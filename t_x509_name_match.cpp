#include "fetchmail.h"

#include <cstdlib>
#include <cstdio>
#include <cstring>

static int verbose;

/* print test and return true on failure */
static int test(const char *p1, const char *p2, int expect) {
    int match = name_match(p1, p2);
    if (verbose)
	printf("name_match(\"%s\", \"%s\") == %d (%d expected)\n", p1, p2, match, expect);
    return expect != match;
}

int main(int argc, const char **argv) {
    int rc = 0;

    if (argc > 1 && 0 == strcmp(argv[1], "-v"))
	verbose = 1;

    rc |= test("example.org", "example.org", 1);
    rc |= test("*example.org", "foo.example.org", 0);
    rc |= test("*.example.org", "foo.example.org", 1);
    rc |= test("*.168.23.23", "192.168.23.23", 0);
    rc |= test("*.com", "example.com", 0);
    if (verbose) {
	printf("x509_name_match: ");
	puts(rc ? "FAIL" : "PASS");
    }
    return rc;
}
