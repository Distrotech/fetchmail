#ifndef _FM_UNORDERED_SET_H_
#define _FM_UNORDERED_SET_H_

namespace fetchmail {
    template <typename T> struct uset;
};

// XXX: works with GCC and CLANG
#ifdef __GXX_EXPERIMENTAL_CXX0X__
// C++0x
#include <unordered_set>
template <typename T>
struct fetchmail::uset {
    typedef std::unordered_set<T> type;
};

#else
// use Boost
#include <boost/unordered_set.hpp>
template <typename T>
struct fetchmail::uset {
    typedef boost::unordered_set<T> type;
};
// XXX: could use GCC/G++/libstd++ TR1
#endif
#endif
