#include "IMAPCapa.h"

#include <cstdlib>
#include <iostream>

static bool t_throwifuninit(const IMAPCapa &c) {
    try {
	(void)c["foo"]; // should throw
	return false;
    } catch(...) {
	return true;
    }

}

static bool t_nothrowifinit(const IMAPCapa &c) {
    try {
	(void)c["foo"];
	return true;
    } catch(...) {
	return false;
    }
}

static bool t_matchfoocase(const IMAPCapa &c) { return c["FOO"]; }

static bool t_matchbaricase(const IMAPCapa &c) { return c["bAr"]; }

static bool t_notfound(const IMAPCapa &c) { return !c["NoNeXiSt"]; }

static bool check(const string &name, bool (*func)(const IMAPCapa &c), const IMAPCapa &c, bool verbose) {
    bool result = func(c);
    if (verbose)
	cout << (result ? "- PASS: " : "- FAIL: ") << name << "\n";
    return result;
}

int main() {
    IMAPCapa c;
    string s("FOO BaR\tBAZ");
    bool result = true;
    bool verbose = getenv("TEST_VERBOSE");

    result &= check("if uninitialized access throws exception", t_throwifuninit, c, verbose);
    c.parse("");
    result &= check("if initialized access does not throw exception", t_nothrowifinit, c, verbose);
    c.parse(s);
    if (verbose)
	cout << "- TEST: parsing \"" << s << "\" yields \"" << c.str() << "\"\n";
    result &= check("if we match sensitively", t_matchfoocase, c, verbose);
    result &= check("if we match insensitively", t_matchbaricase, c, verbose);
    result &= check("if we handle not-found properly", t_notfound, c, verbose);
    c.flush();
    result &= check("if uninitialized access throws exception", t_throwifuninit, c, verbose);

    return !result;
}
