#include "NoAuth.h"

namespace session::socks5::detail {

NoAuth::NoAuth(net_tcp::socket& client_socket) : AbstractAuth(client_socket) {}

std::shared_ptr<NoAuth> NoAuth::Create(net_tcp::socket& client_socket) {
  return std::shared_ptr<NoAuth>(new NoAuth(client_socket));
}

void NoAuth::Execute(Callback callback) {
  callback({});
}

}  // namespace session::socks5::detail