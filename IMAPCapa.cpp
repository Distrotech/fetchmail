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
