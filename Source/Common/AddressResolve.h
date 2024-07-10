#ifndef COMMON_ADDRESS_RESOLVE_H_
#define COMMON_ADDRESS_RESOLVE_H_

#include <array>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/endian.hpp>
#include <cstdint>
#include <functional>
#include "Types.h"

namespace common {

#define kIPv4Size 4
#define kIPv6Size 16

using DomainResolverCallbackTCP = std::function<void(const error_code&, const net_tcp::endpoint&)>;
using DomainResolverCallbackUDP = std::function<void(const error_code&, const net_udp::endpoint&)>;

// An auxiliary function for generating an IPv4 endpoint based on the specified address and port.
// Supports TCP and UDP protocols.
// The optional parameter 'big_endian' indicates how the function will interpret the parameters passed
// to it.
// If big_endian == true, the function converts big-endian -> native host endian.
// If big_endian == false, little-endian -> native host endian.
template <typename TEndpoint = net_tcp::endpoint>
TEndpoint GetIPv4Endpoint(uint32_t address, uint16_t port, bool big_endian = true) {
  const auto endian_address =
      big_endian ? boost::endian::big_to_native(address) : boost::endian::little_to_native(address);
  const auto endian_port =
      big_endian ? boost::endian::big_to_native(port) : boost::endian::little_to_native(port);
  TEndpoint endpoint;

  endpoint.address(boost::asio::ip::address_v4(endian_address));
  endpoint.port(endian_port);

  return endpoint;
}

// An auxiliary function for generating an IPv6 endpoint based on the specified address and port.
// Supports TCP and UDP protocols.
// The optional parameter 'big_endian' indicates how the function will interpret the parameters passed
// to it.
// If big_endian == true, the function converts big-endian -> native host endian.
// If big_endian == false, little-endian -> native host endian.
template <typename TEndpoint = net_tcp::endpoint>
TEndpoint GetIPv6Endpoint(const uint8_t* address, uint16_t port, bool big_endian = true) {
  boost::asio::ip::address_v6::bytes_type ipv6_bytes;
  const auto endian_port =
      big_endian ? boost::endian::big_to_native(port) : boost::endian::little_to_native(port);
  TEndpoint endpoint;

  for (size_t cx = 0; cx < ipv6_bytes.size(); ++cx) {
    ipv6_bytes[cx] = address[cx];  // FIXME: out-of-bound
  }

  endpoint.address(boost::asio::ip::address_v6(ipv6_bytes));
  endpoint.port(endian_port);

  return endpoint;
}

// Asynchronous function for domain name resolution.
// Supports TCP and UDP protocols.
template <typename TResolver = net_tcp::resolver, typename TCallback = DomainResolverCallbackTCP>
void ResolveDomainAddress(const boost::asio::any_io_executor& executor, const std::string& address,
                          uint16_t port, TCallback callback) {
  auto resolver = std::make_shared<TResolver>(executor);
  resolver->async_resolve(
      address, std::to_string(port),
      [resolver, callback](const error_code& ecode, typename TResolver::iterator iterator)
      {
        const auto& endpoint = *iterator;
        callback(ecode, endpoint);
      });
}

}  // namespace common

#endif  // !COMMON_ADDRESS_RESOLVE_H_
