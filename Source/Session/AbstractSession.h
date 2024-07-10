#ifndef SESSION_ABSTRACT_SESSION_H_
#define SESSION_ABSTRACT_SESSION_H_

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/core/span.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include "Configuration.h"
#include "Types.h"

// Forward declaration
class Server;

namespace session {

class AbstractSession : public std::enable_shared_from_this<AbstractSession> {
 public:
  // Type of session ID.
  using session_id = size_t;

  // A value indicating an invalid session ID
  static constexpr session_id kInvalidId = -1;

  AbstractSession(session_id id, const std::weak_ptr<Server>& server, net_tcp::socket&& client_socket);
  virtual ~AbstractSession() = default;

  AbstractSession(const AbstractSession&) = delete;
  AbstractSession& operator=(const AbstractSession&) = delete;
  AbstractSession(AbstractSession&&) noexcept = delete;
  AbstractSession& operator=(AbstractSession&&) noexcept = delete;

  // Starting the session.
  virtual void Start() = 0;

  // Stops the session, closes all connections.
  // After that, the session is no longer usable, regardless of calling Start again.
  virtual void Stop() = 0;

 protected:
  using log_level = boost::log::trivial::severity_level;

  const net_tcp::endpoint kEmptyTcpEndpoint;
  const net_udp::endpoint kEmptyUdpEndpoint;

  static constexpr size_t kTcpBufferSize = 4096;
  static constexpr size_t kUdpBufferSize = 65535;

  // Performs tunneling of traffic between source <-> dest.
  void DoTunnelingTraffic(net_tcp::socket& source, net_tcp::socket& dest, boost::span<char> buffer);

  // Reads data from the source socket to the buffer, then sends it to the dest socket.
  void DoTunnelingReceive(net_tcp::socket& source, net_tcp::socket& dest, boost::span<char> buffer);

  // Sends the specified data size from the buffer and sends it to the dest socket,
  // after which it calls the DoTunnelingReceive method.
  void DoTunnelingSend(net_tcp::socket& source, net_tcp::socket& dest, boost::span<char> buffer,
                       size_t size_to_send);

  // Outputs message to the log.
  void LogMessage(log_level level, const std::string& message) const;

  // Deletes session from the server.
  // It has optional parameters for log output. If the 'message' is empty, the log will not
  // be recorded.
  void DeleteSession(log_level level = log_level::info, const std::string& message = "") const;

  session_id session_id_;
  net_tcp::socket tcp_socket_client_;
  std::shared_ptr<Configuration> config_;

 private:
  std::weak_ptr<Server> server_;
  bool tunneling_started_;
};

}  // namespace session

#endif  // !SESSION_ABSTRACT_SESSION_H_
