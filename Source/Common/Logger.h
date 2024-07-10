#ifndef COMMON_LOGGER_H_
#define COMMON_LOGGER_H_

#include <boost/log/trivial.hpp>

#define WLOGGER(level) BOOST_LOG_TRIVIAL(level) << "[" << __FUNCTION__ << ":" << __LINE__ << "]: "

#endif  // !COMMON_LOGGER_H_
