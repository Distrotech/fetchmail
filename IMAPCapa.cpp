/*
 * IMAPCapa.cpp
 *
 *  Created on: 19.03.2011
 *      Author: mandree
 */

#include "IMAPCapa.h"

#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include <string>
#include <set>
#include <algorithm>

using namespace std;
using namespace boost;

IMAPCapa::~IMAPCapa() {
    // void
}

//!
void IMAPCapa::parse(const string &capa)
{
    capabilities.clear();

    typedef tokenizer<char_separator<char> > tokenizer;
    char_separator<char> sep(" \t");
    string c = to_upper_copy(capa);
    // warning - to not use to_upper_copy as argument for the tokenizer constructor!
    // doing so causes invalid memory accesses galore (check valgrind!)
    tokenizer tokens(c, sep);

    copy(tokens.begin(), tokens.end(), inserter(capabilities, capabilities.begin()));
    havecapabilities = true;
}

#ifdef TEST
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

static bool check(const string &name, bool (*func)(const IMAPCapa &c), const IMAPCapa &c) {
    bool result = func(c);
    cout << (result ? "- PASS: " : "- FAIL: ") << name << "\n";
    return result;
}

int main() {
    IMAPCapa c;
    string s("FOO BaR\tBAZ");
    bool result = true;

    result &= check("if uninitialized access throws exception", t_throwifuninit, c);
    c.parse("");
    result &= check("if initialized access does not throw exception", t_nothrowifinit, c);
    c.parse(s);
    cout << "- TEST: parsing \"" << s << "\" yields \"" << c.str() << "\"\n";
    result &= check("if we match sensitively", t_matchfoocase, c);
    result &= check("if we match insensitively", t_matchbaricase, c);
    result &= check("if we handle not-found properly", t_notfound, c);
    c.flush();
    result &= check("if uninitialized access throws exception", t_throwifuninit, c);

    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif
