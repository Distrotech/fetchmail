#include "fetchmail.h"
#include <stdio.h>

int main(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
	printf("%s: %s\n", argv[i], rfc822_valid_msgid((unsigned char *)argv[i]) ? "OK" : "INVALID");
    }
    return 0;
}
