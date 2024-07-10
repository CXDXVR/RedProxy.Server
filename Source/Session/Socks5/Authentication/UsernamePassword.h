#ifndef SESSSION_SOCKS5_AUTH_USER_PASSWORD_H_
#define SESSSION_SOCKS5_AUTH_USER_PASSWORD_H_

#include <vector>
#include "AbstractAuth.h"

namespace session::socks5::detail {

class UsernamePassword final : public AbstractAuth {
  static constexpr size_t kSizeOfNegotiation = 513;

  struct Credentials {
    std::string username;
    std::string password;
  };

  UsernamePassword(net_tcp::socket& client_socket);

 public:
  ~UsernamePassword() = default;

  UsernamePassword(const UsernamePassword&) = delete;
  UsernamePassword& operator=(const UsernamePassword&) = delete;
  UsernamePassword(UsernamePassword&&) noexcept = delete;
  UsernamePassword& operator=(UsernamePassword&&) noexcept = delete;

  // Creates and returns an instance of the class.
  static std::shared_ptr<UsernamePassword> Create(net_tcp::socket& client_socket);

  // Starts the authentication process.
  void Execute(Callback callback) override;

 private:
  // Extracts credentials from the buffer.
  Credentials GetCredentials() const;

  std::vector<char> buffer_;
};

}  // namespace session::socks5::detail

#endif  // !SESSSION_SOCKS5_AUTH_USER_PASSWORD_H_
