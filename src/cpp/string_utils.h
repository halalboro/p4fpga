#ifndef FPGA_STRING_UTILS_H
#define FPGA_STRING_UTILS_H

#include "common.h"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cctype>

namespace SV {

/// Return `source` as a_string_in_snake_case.
cstring SnakeCase(const cstring& source);

/// Return `source` as AStringInCamelCase.
cstring CamelCase(const cstring& source);

/// Return `source` as aStringInCamelCase.
cstring camelCase(const cstring& source);

/// Return `source` as ASTRINGINUPPERCASE.
cstring UpperCase(const cstring& source);

/// Return `source` with '.' replaced with '$'
cstring RemoveDot(const cstring& source);

// Join a vector of elements by a delimiter object. ostream<< must be defined
// for both class S and T and an ostream, as it is e.g. in the case of strings
// and character arrays
template<class S, class T>
std::string join(std::vector<T>& elems, S& delim) {
    std::stringstream ss;
    typename std::vector<T>::iterator e = elems.begin();
    
    if (e != elems.end()) {
        ss << *e++;
        for (; e != elems.end(); ++e) {
            ss << delim << *e;
        }
    }
    return ss.str();
}

}  // namespace SV

#endif // FPGA_STRING_UTILS_H