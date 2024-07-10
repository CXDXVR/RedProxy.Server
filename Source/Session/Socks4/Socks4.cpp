#include "Socks4.h"
#include <boost/asio/write.hpp>
#include <boost/core/span.hpp>
#include <boost/endian.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include "Common/Strings.h"
#include "Configuration.h"

namespace session::socks4 {
namespace {

// A function to check the transmitted buffer for the correctness of the SOCKS4 message.
bool IsValidMessage(const boost::span<char> data) {
  if (data.size() >= sizeof(Message)) {
    auto raw_header = reinterpret_cast<const Message*>(data.data());

    return raw_header->version == 0x4 &&
               (raw_header->command >= static_cast<uint8_t>(Command::kConnect) &&
                raw_header->command <= static_cast<uint8_t>(Command::kBind)) ||
           (raw_header->status >= static_cast<uint8_t>(ReplyCode::kGranted) &&
            raw_header->status <= static_cast<uint8_t>(ReplyCode::kClientConflict));
  }

  return false;
}

}  // namespace

Socks4Session::Socks4Session(session_id id, const std::weak_ptr<Server>& server,
                             net_tcp::socket&& client_socket)
    : AbstractSession(id, server, std::move(client_socket)),
      tcp_socket_application_{tcp_socket_client_.get_executor()},
      tcp_acceptor_bind_{tcp_socket_client_.get_executor()},
      buffer_{},
      user_id_{} {}

std::shared_ptr<Socks4Session> Socks4Session::Create(session_id id, const std::weak_ptr<Server>& server,
                                                     net_tcp::socket&& client_socket) {
  return std::shared_ptr<Socks4Session>(new Socks4Session(id, server, std::move(client_socket)));
}

void Socks4Session::Start() {
  // After connecting, the client sends the following message:
  //		    +----+----+----+----+----+----+----+----+....+------+
  //            | VN | CD | DSTPORT | DSTIP   | USERID       | NULL |
  //            +----+----+----+----+----+----+----+----+....+------+
  // #of bytes :  1    1       2         4      variable        1
  buffer_.resize(kTcpBufferSize);
  tcp_socket_client_.async_read_some(
      boost::asio::buffer(buffer_),
      [this, self = shared_from_this()](const error_code& ecode, size_t size)
      {
        if (ecode) {
          DeleteSession(
              log_level::error,
              (boost::format("Error reading the authentication message: %s.") % ecode.message())
                  .str());
        } else if (!IsValidMessage({buffer_.data(), size})) {
          DeleteSession(log_level::error, "Invalid authentication message.");
        } else {
          DoProcessAuthentication();
        }
      });
}

void Socks4Session::Stop() {
  error_code ecode;
  tcp_acceptor_bind_.close(ecode);
  tcp_socket_client_.close(ecode);
  tcp_socket_application_.close(ecode);
}

void Socks4Session::DoProcessAuthentication() {
  // Extracting the USER-ID from the message.
  user_id_ = common::GetStringFromArray(buffer_, sizeof(Message));

  if (!config_->GetSocks4().user_id.empty() && user_id_ != config_->GetSocks4().user_id) {
    DoSendReplyAndDeleteSession(ReplyCode::kClientConflict, kEmptyTcpEndpoint, log_level::error,
                                (boost::format("Incorrect USER-ID '%s'.") % user_id_).str());
  } else {
    DoExecuteCommand();
  }
}

void Socks4Session::DoExecuteCommand() {
  auto message = reinterpret_cast<const Message*>(buffer_.data());
  switch (static_cast<Command>(message->command)) {
    case Command::kConnect:
      // The client connects to the SOCKS server and sends a CONNECT request when
      // it wants to establish a connection to an application server.
      if (!config_->GetSocks4().enable_connect) {
        DoSendReplyAndDeleteSession(
            ReplyCode::kRejected, kEmptyTcpEndpoint, log_level::error,
            "The CONNECT command is disabled in the application configuration.");
      } else {
        DoConnectCommand();
      }
      break;
    case Command::kBind:
      // The client connects to the SOCKS server and sends a BIND request when
      // it wants to prepare for an inbound connection from an application server.
      // This should only happen after a primary connection to the application
      // server has been established with a CONNECT. Typically, this is part of
      // the sequence of actions:
      //
      // -bind(): obtain a socket
      // -getsockname(): get the IP address and port number of the socket
      // -listen(): ready to accept call from the application server
      // -use the primary connection to inform the application server of
      // the IP address and the port number that it should connect to.
      // -accept(): accept a connection from the application server
      //
      // The purpose of SOCKS BIND operation is to support such a sequence
      // but using a socket on the SOCKS server rather than on the client.
      if (!config_->GetSocks4().enable_bind) {
        DoSendReplyAndDeleteSession(
            ReplyCode::kRejected, kEmptyTcpEndpoint, log_level::error,
            "The BIND command is disabled in the application configuration.");
      } else {
        DoBindCommand();
      }
      break;
  }
}

void Socks4Session::DoConnectCommand() {
  DoResolveAddress(
      [this, self = shared_from_this()](const error_code& ecode, const net_tcp::endpoint& endpoint)
      {
        if (ecode) {
          DoSendReplyAndDeleteSession(
              ReplyCode::kConnectionFailed, kEmptyTcpEndpoint, log_level::error,
              (boost::format("Domain Name resolution error: %s.") % ecode.message()).str());
        } else {
          tcp_socket_application_.async_connect(
              endpoint,
              [this, self, endpoint](const error_code& ecode)
              {
                if (ecode) {
                  DoSendReplyAndDeleteSession(
                      ReplyCode::kConnectionFailed, kEmptyTcpEndpoint, log_level::error,
                      (boost::format("Server connection error [%s:%d]: %s.") %
                       endpoint.address().to_string() % endpoint.port() % ecode.message())
                          .str());
                } else {
                  DoSendReply(
                      ReplyCode::kGranted, tcp_socket_application_.remote_endpoint(),
                      [this, self]()
                      {
                        LogMessage(
                            log_level::info,
                            (boost::format(
                                 "Running the CONNECT command, client=%s:%d, server=%s:%d.") %
                             tcp_socket_client_.remote_endpoint().address().to_string() %
                             tcp_socket_client_.remote_endpoint().port() %
                             tcp_socket_application_.remote_endpoint().address().to_string() %
                             tcp_socket_application_.remote_endpoint().port())
                                .str());

                        DoTunnelingTraffic(tcp_socket_client_, tcp_socket_application_,
                                           boost::span<char>{buffer_.data(), buffer_.size()});
                        DoTunnelingTraffic(tcp_socket_application_, tcp_socket_client_,
                                           boost::span<char>{buffer_.data(), buffer_.size()});
                      });
                }
              });
        }
      });
}

void Socks4Session::DoBindCommand() {
  // Configures the listener to receive incoming connections and sends its local address
  // to the client.
  tcp_acceptor_bind_.open(net_tcp::v4());
  tcp_acceptor_bind_.bind(net_tcp::endpoint(net_tcp::v4(), 0));
  tcp_acceptor_bind_.listen(1);

  DoSendReply(
      ReplyCode::kGranted, tcp_acceptor_bind_.local_endpoint(),
      [this, self = shared_from_this()]()
      {
        tcp_acceptor_bind_.async_accept(
            tcp_socket_application_,
            [this, self](const error_code& ecode)
            {
              error_code ecode_ignore;
              tcp_acceptor_bind_.close(ecode_ignore);

              if (ecode) {
                DoSendReplyAndDeleteSession(
                    ReplyCode::kConnectionFailed, kEmptyTcpEndpoint, log_level::error,
                    (boost::format("Failed to accept incoming connection in BIND command: %s.") %
                     ecode.message())
                        .str());
              } else {
                DoSendReply(
                    ReplyCode::kGranted, tcp_socket_application_.remote_endpoint(),
                    [this, self]()
                    {
                      LogMessage(
                          log_level::info,
                          (boost::format("Running the BIND command, client=%s:%d, server=%s:%d.") %
                           tcp_socket_client_.remote_endpoint().address().to_string() %
                           tcp_socket_client_.remote_endpoint().port() %
                           tcp_socket_application_.remote_endpoint().address().to_string() %
                           tcp_socket_application_.remote_endpoint().port())
                              .str());

                      DoTunnelingTraffic(tcp_socket_client_, tcp_socket_application_,
                                         boost::span<char>{buffer_.data(), buffer_.size()});
                      DoTunnelingTraffic(tcp_socket_application_, tcp_socket_client_,
                                         boost::span<char>{buffer_.data(), buffer_.size()});
                    });
              }
            });
      });
}

void Socks4Session::DoSendReply(ReplyCode code, const net_tcp::endpoint& endpoint,
                                Callback callback) {
  Message message{0x0, static_cast<uint8_t>(code), boost::endian::native_to_big(endpoint.port()),
                  boost::endian::native_to_big(endpoint.address().to_v4().to_uint())};

  boost::asio::async_write(
      tcp_socket_client_, boost::asio::buffer(&message, sizeof(message)),
      [this, self = shared_from_this(), callback](const error_code& ecode, size_t)
      {
        if (ecode) {
          DeleteSession(
              log_level::error,
              (boost::format("Error sending a response to the client: %s") % ecode.message())
                  .str());
        } else {
          callback();
        }
      });
}

void Socks4Session::DoSendReplyAndDeleteSession(ReplyCode code, const net_tcp::endpoint& endpoint,
                                                log_level level, const std::string& message) {
  DoSendReply(code, endpoint,
              [this, self = shared_from_this(), level, message]()
              { DeleteSession(level, message); });
}

void Socks4Session::DoResolveAddress(common::DomainResolverCallbackTCP callback) {
  auto message = reinterpret_cast<const Message*>(buffer_.data());
  // For version 4A, if the client cannot resolve the destination host's domain name to find its IP address,
  // it should set the first three bytes of DST-IP to NULL and the last byte to a non-zero value. (This corresponds
  // to IP address 0.0.0.x, with x nonzero.
  if ((boost::endian::big_to_native(message->address) ^ 0x000000ff) < 0xff) {
    const auto address =
        common::GetStringFromArray(buffer_, sizeof(Message) + user_id_.length() + 1 /* \0 char */);
    const auto service = boost::endian::big_to_native(message->port);

    common::ResolveDomainAddress<net_tcp::resolver>(tcp_socket_client_.get_executor(), address,
                                                    service, callback);
  } else {
    callback({}, common::GetIPv4Endpoint(message->address, message->port));
  }
}

}  // namespace session::socks4