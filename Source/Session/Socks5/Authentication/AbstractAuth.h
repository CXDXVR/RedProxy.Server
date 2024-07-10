#ifndef SESSSION_SOCKS5_AUTH_ABSTRACT_H_
#define SESSSION_SOCKS5_AUTH_ABSTRACT_H_

#include <boost/asio/ip/tcp.hpp>
#include <memory>
#include "Types.h"

namespace session::socks5::detail {

class AbstractAuth : public std::enable_shared_from_this<AbstractAuth> {
 public:
  // Callback is a function called after the authentication procedure, regardless of its result.
  // If the authentication data is incorrect, the error will have the status
  // boost::asio::error::access_denied.
  using Callback = std::function<void(const error_code&)>;

  AbstractAuth(net_tcp::socket& client_socket) : tcp_socket_client_{client_socket} {};
  virtual ~AbstractAuth() = default;

  // Starts the authentication process.
  virtual void Execute(Callback callback) = 0;

 protected:
  net_tcp::socket& tcp_socket_client_;
};

}  // namespace session::socks5::detail

#endif  // !SESSSION_SOCKS5_AUTH_ABSTRACT_H_
