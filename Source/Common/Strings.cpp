#include "Strings.h"
#include <algorithm>

namespace common {

std::string GetStringFromArray(const boost::span<char> data, size_t offset) {
  if (data.size() > offset) {
    auto string_begin = data.begin() + offset;
    auto string_end = std::find(string_begin, data.end(), '\0');

    if (string_end < data.end()) {
      return {string_begin, string_end};
    }
  }

  return {};
}

}  // namespace common