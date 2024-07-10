#ifndef SESSSION_SOCKS5_AUTH_NONE_H_
#define SESSSION_SOCKS5_AUTH_NONE_H_

#include "AbstractAuth.h"

namespace session::socks5::detail {

class NoAuth final : public AbstractAuth {
  NoAuth(net_tcp::socket& client_socket);

 public:
  ~NoAuth() = default;

  NoAuth(const NoAuth&) = delete;
  NoAuth& operator=(const NoAuth&) = delete;
  NoAuth(NoAuth&&) noexcept = delete;
  NoAuth& operator=(NoAuth&&) noexcept = delete;

   // Creates and returns an instance of the class.
  static std::shared_ptr<NoAuth> Create(net_tcp::socket& client_socket);

  // Starts the authentication process.
  void Execute(Callback callback) override;
};

}  // namespace session::socks5::detail

#endif  // !SESSSION_SOCKS5_AUTH_NONE_H_
