/*
 * IMAPCapa.h
 *
 *  Created on: 19.03.2011
 *      Author: mandree
 */

#ifndef IMAPCAPA_H_
#define IMAPCAPA_H_

#include <boost/tr1/unordered_set.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace boost;

typedef std::tr1::unordered_set<string> sosT;

class IMAPCapa {
private:
    sosT capabilities;
    bool havecapabilities;

public:
    IMAPCapa() : havecapabilities(false) { };
    IMAPCapa(const string &capas) { parse(capas); }

    bool havecapa(void) const { return havecapabilities; }
    bool operator[] (const string &capa) const {
	if (!havecapabilities) throw(string("IMAPCapa::operator[]: no capabilities parsed, use parse(const string &) first!"));
	return capabilities.find(to_upper_copy(capa)) != capabilities.end();
    }

    void parse(const string &);

    void flush() { capabilities.clear(); havecapabilities = false; }

    string str(void) const {
	stringstream ss;
	copy(capabilities.begin(), capabilities.end(), ostream_iterator<string>(ss, " "));
	return ss.rdbuf()->str();
    }

    virtual ~IMAPCapa();
};

#endif /* IMAPCAPA_H_ */
