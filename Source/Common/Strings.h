#ifndef COMMON_STRINGS_H_
#define COMMON_STRINGS_H_

#include <boost/core/span.hpp>
#include <string>
#include <vector>

namespace common {

// A function for safely extracting a string from an array
std::string GetStringFromArray(const boost::span<char> data, size_t offset = 0);

}  // namespace common

#endif  // !COMMON_STRINGS_H_
