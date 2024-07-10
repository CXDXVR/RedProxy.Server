#ifndef SESSION_SOCKS4_H_
#define SESSION_SOCKS4_H_

#include <vector>
#include "Common/AddressResolve.h"
#include "Session/AbstractSession.h"
#include "Session/Socks4/Socks4Types.h"

namespace session::socks4 {

class Socks4Session final : public AbstractSession {
  using Callback = std::function<void()>;

  Socks4Session(session_id id, const std::weak_ptr<Server>& server,
                net_tcp::socket&& client_socket);

 public:
  ~Socks4Session() = default;

  // Creates and returns an instance of the session.
  static std::shared_ptr<Socks4Session> Create(session_id id, const std::weak_ptr<Server>& server,
                                               net_tcp::socket&& client_socket);

  // Starting the session.
  void Start() override;

  // Stops the session, closes all connections.
  // After that, the session is no longer usable, regardless of calling Start again.
  void Stop() override;

 private:
  // The method that processes the first message from the client.
  // The main task is to verify the correctness of the header, extract and process
  // the USER-ID (user authentication).
  // If successful, passes control to the DoExecuteCommand_ method.
  void DoProcessAuthentication();

  // Processes the message received from the client and transfers control to a specific
  // command (CONNECT or BIND).
  // If successful, passes control to the DoConnectCommand_ or DoBindCommand_ method.
  void DoExecuteCommand();

  // CONNECT command handler.
  void DoConnectCommand();

  // BIND command handler.
  void DoBindCommand();

  // Sends a response to the client, then passes control to the callback function.
  // In case of failure, deletes the current session without transferring control to the
  // callback function.
  void DoSendReply(ReplyCode code, const net_tcp::endpoint& endpoint, Callback callback);

  // Sends a response to the client and deletes the current session.
  // It has 2 optional parameters 'log_level' and 'message' for log output.
  // If the 'message' parameter is empty, the log will not be recorded.
  void DoSendReplyAndDeleteSession(ReplyCode code, const net_tcp::endpoint& endpoint,
                                   log_level level = log_level::info,
                                   const std::string& message = "");

  // Extracts and processes the target application address from the request.
  void DoResolveAddress(common::DomainResolverCallbackTCP callback);

  net_tcp::socket tcp_socket_application_;
  net_tcp::acceptor tcp_acceptor_bind_;
  std::vector<char> buffer_;
  std::string user_id_;
};

}  // namespace session::socks4

#endif  // !SESSION_SOCKS4_H_
