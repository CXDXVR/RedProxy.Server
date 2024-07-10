#ifndef TYPES_H_
#define TYPES_H_

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

using net_tcp = boost::asio::ip::tcp;
using net_udp = boost::asio::ip::udp;

using error_code = boost::system::error_code;

#endif  // !TYPES_H_
