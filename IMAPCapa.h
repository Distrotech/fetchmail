/*
 * IMAPCapa.h
 *
 *  Created on: 19.03.2011
 *      Author: mandree
 */

#ifndef IMAPCAPA_H_
#define IMAPCAPA_H_

#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace boost;

typedef set<string> sosT;

class IMAPCapa {
private:
    sosT capabilities;
    bool havecapabilities;

public:
    inline IMAPCapa() { havecapabilities = false; }
    inline IMAPCapa(const string &capas) { parse(capas); }

    inline bool havecapa(void) const { return havecapabilities; }
    bool operator[] (const string &capa) const {
	if (!havecapabilities) throw(string("IMAPCapa::operator[]: no capabilities parsed, use parse(const string &) first!"));
	return capabilities.find(to_upper_copy(capa)) != capabilities.end();
    }

    inline string str(void) const {
	vector<string> sv;
	stringstream ss;
	copy(capabilities.begin(), capabilities.end(), ostream_iterator<string>(ss, " "));
	return ss.rdbuf()->str();
    }

    inline void flush() { capabilities.clear(); havecapabilities = false; }

    void parse(const string &);

    virtual ~IMAPCapa();
};

#endif /* IMAPCAPA_H_ */
