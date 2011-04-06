#include "fetchmail.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

const char *program_name;

int main(int argc, char **argv) {
    char *t;

    program_name = "t_rfc2047e";

    if (argc > 1) {
	t = rfc2047e(argv[1], argc > 2 ? argv[2] : "utf-8");
	cout << " input: \"" << argv[1] << "\"\n"
	     << "output: \"" << t       << "\"\n";
	free(t);
    }
    return EXIT_SUCCESS;
}
