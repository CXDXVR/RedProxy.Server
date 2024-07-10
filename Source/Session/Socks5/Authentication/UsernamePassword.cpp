#include "UsernamePassword.h"
#include <boost/asio/write.hpp>
#include <boost/core/span.hpp>
#include "Configuration.h"

namespace session::socks5::detail {

namespace {

bool IsValidMessage(boost::span<char> data) {
  return true;
}

}  // namespace

UsernamePassword::UsernamePassword(net_tcp::socket& client_socket) : AbstractAuth(client_socket) {}

std::shared_ptr<UsernamePassword> UsernamePassword::Create(net_tcp::socket& client_socket) {
  return std::shared_ptr<UsernamePassword>(new UsernamePassword(client_socket));
}

void UsernamePassword::Execute(Callback callback) {
  buffer_.resize(kSizeOfNegotiation);
  tcp_socket_client_.async_read_some(
      boost::asio::buffer(buffer_),
      [this, self = shared_from_this(), callback](const error_code& ecode, size_t size)
      {
        if (ecode) {
          callback(ecode);
        } else if (!IsValidMessage({buffer_.data(), size})) {
          callback(boost::asio::error::access_denied);
        } else {
          auto [username, password] = GetCredentials();
          bool success = username == Configuration::GetInstance()->GetSocks5().username &&
                         password == Configuration::GetInstance()->GetSocks5().password;
          uint8_t reply[2]{0, !success};  // [0] - version, must be 0. [1] - status, 0 for success.

          boost::asio::async_write(
              tcp_socket_client_, boost::asio::buffer(reply),
              [this, self, success, callback](const error_code& ecode, size_t)
              { callback(success ? ecode : boost::asio::error::access_denied); });
        }
      });
}

UsernamePassword::Credentials UsernamePassword::GetCredentials() const {
  const char* username_begin = buffer_.data() + sizeof(uint8_t) * 2;
  const uint8_t username_len = *reinterpret_cast<const uint8_t*>(buffer_.data() + sizeof(uint8_t));

  const char* password_begin = username_begin + username_len + sizeof(uint8_t);
  const uint8_t password_len = *reinterpret_cast<const uint8_t*>(username_begin + username_len);

  return {std::string(username_begin, username_len), std::string(password_begin, password_len)};
}

}  // namespace session::socks5::detail