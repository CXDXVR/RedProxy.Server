#ifndef SERVER_H_
#define SERVER_H_

#include <boost/asio/io_context.hpp>
#include <map>
#include <memory>
#include "Session/AbstractSession.h"
#include "Types.h"

class Server final : public std::enable_shared_from_this<Server> {
 public:
  // SOCKS Server version.
  enum class Version { kSocks4, kSocks5 };

  // Type of session ID.
  using session_id = session::AbstractSession::session_id;

 private:
  Server(boost::asio::io_context& context, const net_tcp::endpoint& endpoint, Version version);

 public:
  ~Server() = default;

  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;
  Server(Server&&) noexcept = delete;
  Server& operator=(Server&&) noexcept = delete;

  // Creates an instance of the class of the specified version of the SOCKS server.
  static std::shared_ptr<Server> Create(boost::asio::io_context& context,
                                        const net_tcp::endpoint& endpoint, Version version);

  // Starts the listener to accept incoming connections.
  void Start();

  // Stops the listener.
  void Stop();

  // Returns true if the listener is active.
  bool IsOpen() const;

  // Closes the connection and deletes the specified session.
  void DeleteSession(session_id id);

 private:
  // Generates a unique session ID. Returns the kInvalidId in case of failure.
  session_id GenerateSessionId();

  Version version_;
  net_tcp::endpoint tcp_endpoint_;
  net_tcp::acceptor tcp_acceptor_;
  std::map<session_id, std::shared_ptr<session::AbstractSession>> sessions_;
};

#endif  // SERVER_H_
