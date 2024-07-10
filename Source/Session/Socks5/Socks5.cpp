#include "Socks5.h"
#include <boost/asio/write.hpp>
#include <boost/endian.hpp>
#include <set>
#include "../../Common/Strings.h"
#include "Authentication/AbstractAuth.h"
#include "Authentication/NoAuth.h"
#include "Authentication/UsernamePassword.h"

namespace session::socks5 {
namespace {

// Checks the SOCKS5 authentication message for correctness.
bool IsValidAuthMessage(const boost::span<char> data) {
  if (data.size() > sizeof(AuthenticationMessage)) {
    auto header = reinterpret_cast<const AuthenticationMessage*>(data.data());

    return header->version == 0x5 && header->count > 0 &&
           (data.size() - sizeof(AuthenticationMessage)) >= header->count;
  }

  return false;
}

// Checks the SOCKS5 TCP message for correctness.
bool IsValidTcpMessage(const boost::span<char> data) {
  if (data.size() > sizeof(TcpMessage)) {
    auto raw_message = reinterpret_cast<const TcpMessage*>(data.data());
    if (raw_message->version == 0x5 &&
        raw_message->command >= static_cast<uint8_t>(Command::kConnect) &&
        raw_message->command <= static_cast<uint8_t>(Command::kUdpAssociate)) {
      switch (static_cast<AddressType>(raw_message->address_type)) {
        case AddressType::kIPv4:
          return data.size() >= sizeof(TcpMessage) + sizeof(AddressV4);
        case AddressType::kIPv6:
          return data.size() >= sizeof(TcpMessage) + sizeof(AddressV6);
        case AddressType::kDomainName:
          return data.size() >= sizeof(TcpMessage) + sizeof(AddressDomain);
      }
    }
  }

  return false;
}

std::shared_ptr<std::vector<uint8_t>> CreateUdpMessage(const net_udp::endpoint& endpoint) {
  auto message = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(sizeof(UdpMessage)));
  auto raw_message = reinterpret_cast<UdpMessage*>(message->data());

  raw_message->reserved = 0x0;
  raw_message->fragment = 0;
  raw_message->address_type =
      static_cast<uint8_t>(endpoint.address().is_v4() ? AddressType::kIPv4 : AddressType::kIPv6);

  if (endpoint.address().is_v4()) {
    auto address = boost::endian::native_to_big(endpoint.address().to_v4().to_uint());

    message->insert(message->end(), reinterpret_cast<uint8_t*>(&address),
                    reinterpret_cast<uint8_t*>(&address) + sizeof(address));
  } else {
    auto address = endpoint.address().to_v6().to_bytes();

    message->insert(message->end(), reinterpret_cast<uint8_t*>(address.data()),
                    reinterpret_cast<uint8_t*>(address.data()) + address.size());
  }

  auto service = boost::endian::native_to_big(endpoint.port());

  message->insert(message->end(), reinterpret_cast<uint8_t*>(&service),
                  reinterpret_cast<uint8_t*>(&service) + sizeof(service));

  return message;
}

}  // namespace

Socks5Session::Socks5Session(session_id id, const std::weak_ptr<Server>& server,
                             net_tcp::socket&& socket)
    : AbstractSession(id, server, std::move(socket)),
      buffer_{},
      tcp_socket_application_{tcp_socket_client_.get_executor()},
      tcp_acceptor_bind_{tcp_socket_client_.get_executor()},
      udp_socket_{tcp_socket_client_.get_executor()},
      udp_endpoint_client_{},
      udp_endpoint_application_{} {}

std::shared_ptr<Socks5Session> Socks5Session::Create(session_id id,
                                                     const std::weak_ptr<Server>& server,
                                                     net_tcp::socket&& socket) {
  return std::shared_ptr<Socks5Session>(new Socks5Session(id, server, std::move(socket)));
}

void Socks5Session::Start() {
  // The client connects to the server, and sends a version identifier/method selection message:
  // +-----+----------+----------+
  // | VER | NMETHODS |  METHODS |
  // +-----+----------+----------+
  // |	1  |	1 	  | 1 to 255 |
  // +-----+----------+----------+
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
        } else if (!IsValidAuthMessage({buffer_.data(), size})) {
          DeleteSession(log_level::error, "Invalid authentication message.");
        } else {
          DoProcessAuthentication();
        }
      });
}

void Socks5Session::Stop() {
  error_code ecode;
  tcp_acceptor_bind_.close(ecode);
  tcp_socket_client_.close(ecode);
  tcp_socket_application_.close(ecode);
  udp_socket_.close(ecode);
}

void Socks5Session::DoProcessAuthentication() {
  auto methods = std::set<AuthenticationMethod>();
  auto raw_message = reinterpret_cast<AuthenticationMessage*>(buffer_.data());
  const auto raw_methods_begin = buffer_.data() + sizeof(AuthenticationMessage);

  // Create a list of authorization methods.
  for (uint8_t method_index = 0; method_index < raw_message->count; ++method_index) {
    methods.insert(static_cast<AuthenticationMethod>(raw_methods_begin[method_index]));
  }

  // Looking for a suitable authentication method from the list
  std::shared_ptr<detail::AbstractAuth> auth_executor;
  if (!config_->GetSocks5().username.empty() && !config_->GetSocks5().password.empty()) {
    if (methods.find(AuthenticationMethod::kUserPassword) != methods.end()) {
      raw_message->method = static_cast<uint8_t>(AuthenticationMethod::kUserPassword);
      auth_executor = detail::UsernamePassword::Create(tcp_socket_client_);
    }
  } else if (methods.find(AuthenticationMethod::kNoAuth) != methods.end()) {
    raw_message->method = static_cast<uint8_t>(AuthenticationMethod::kNoAuth);
    auth_executor = detail::NoAuth::Create(tcp_socket_client_);
  }

  if (!auth_executor) {
    DeleteSession(log_level::error, "A suitable authentication method was not found.");
  } else {
    boost::asio::async_write(
        tcp_socket_client_, boost::asio::buffer(buffer_.data(), sizeof(AuthenticationMessage)),
        [this, self = shared_from_this(), auth_executor](const error_code& ecode, size_t size)
        {
          if (ecode) {
            DeleteSession(
                log_level::error,
                (boost::format("Failed to send authentication method: %s.") % ecode.message())
                    .str());
          } else {
            auth_executor->Execute(
                [this, self](const error_code& ecode)
                {
                  if (ecode) {
                    DeleteSession(
                        log_level::error,
                        (boost::format("Authentication error: %s.") % ecode.message()).str());
                  } else {
                    DoExecuteCommand_();
                  }
                });
          }
        });
  }
}

void Socks5Session::DoExecuteCommand_() {
  // Once the method-dependent subnegotiation has completed, the client sends the request details.
  // The SOCKS request is formed as follows:
  // +-----+-----+-------+------+----------+----------+
  // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  // +-----+-----+-------+------+----------+----------+
  // |	1  |  1  | X'00' |   1  | Variable |	2     |
  // +-----+-----+-------+------+----------+----------+
  tcp_socket_client_.async_read_some(
      boost::asio::buffer(buffer_),
      [this, self = shared_from_this()](const error_code& ecode, size_t size)
      {
        if (ecode) {
          DeleteSession(
              log_level::error,
              (boost::format("Error reading the command request: %s.") % ecode.message()).str());
        } else if (!IsValidTcpMessage({buffer_.data(), size})) {
          DeleteSession(log_level::error, "Invalid command message.");
        } else {
          auto message = reinterpret_cast<const TcpMessage*>(buffer_.data());
          switch (static_cast<Command>(message->command)) {
            case Command::kConnect:
              if (!config_->GetSocks5().enable_connect) {
                DoSendReplyAndDeleteSession_(
                    ReplyCode::kNotAllowed, kEmptyTcpEndpoint, log_level::error,
                    "The CONNECT command is disabled in the application configuration.");
              } else {
                DoConnectCommand();
              }
              break;
            case Command::kBind:
              // The BIND request is used in protocols which require the client to
              // accept connections from the server. FTP is a well - known example,
              // which uses the primary client-to-server connection for commands and
              // status reports, but may use a server-to-client connection for
              // transferring data on demand (e.g. LS, GET, PUT).
              if (!config_->GetSocks5().enable_bind) {
                DoSendReplyAndDeleteSession_(
                    ReplyCode::kNotAllowed, kEmptyTcpEndpoint, log_level::error,
                    "The BIND command is disabled in the application configuration.");
              } else {
                DoBindCommand_();
              }
              break;
            case Command::kUdpAssociate:
              // The UDP ASSOCIATE request is used to establish an association within
              // the UDP relay process to handle UDP datagrams. The DST.ADDR and
              // DST.PORT fields contain the address and port that the client expects
              // to use to send UDP datagrams on for the association.
              if (!config_->GetSocks5().enable_udp) {
                DoSendReplyAndDeleteSession_(
                    ReplyCode::kNotAllowed, kEmptyTcpEndpoint, log_level::error,
                    "The UDP-ASSOCIATE command is disabled in the application configuration.");
              } else {
                DoUdpAssociateCommand_();
              }
              break;
            default:
              DoSendReplyAndDeleteSession_(ReplyCode::kUnknownCommand, kEmptyTcpEndpoint,
                                           log_level::error, "Unknown command.");
              break;
          }
        }
      });
}

void Socks5Session::DoConnectCommand() {
  DoResolveAddress_(
      [this, self = shared_from_this()](const error_code& ecode, const net_tcp::endpoint& endpoint)
      {
        if (ecode) {
          DoSendReplyAndDeleteSession_(
              ReplyCode::kErrorHost, kEmptyTcpEndpoint, log_level::error,
              (boost::format("Domain Name resolution error: %s.") % ecode.message()).str());
        } else {
          tcp_socket_application_.async_connect(
              endpoint,
              [this, self, endpoint](const error_code& ecode)
              {
                if (ecode) {
                  DoSendReplyAndDeleteSession_(
                      ReplyCode::kErrorNet, kEmptyTcpEndpoint, log_level::error,
                      (boost::format("Server connection error [%s:%d]: %s.") %
                       endpoint.address().to_string() % endpoint.port() % ecode.message())
                          .str());
                } else {
                  DoSendReply_(
                      ReplyCode::kOk, tcp_socket_application_.remote_endpoint(),
                      [this, self, endpoint]()
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

void Socks5Session::DoBindCommand_() {
  const auto addr_type =
      static_cast<AddressType>(reinterpret_cast<const TcpMessage*>(buffer_.data())->address_type) ==
              AddressType::kIPv6
          ? net_tcp::v6()
          : net_tcp::v4();

  tcp_acceptor_bind_.open(addr_type);
  tcp_acceptor_bind_.bind(net_tcp::endpoint(addr_type, 0));
  tcp_acceptor_bind_.listen(1);

  DoSendReply_(
      ReplyCode::kOk, tcp_acceptor_bind_.local_endpoint(),
      [this, self = shared_from_this()]()
      {
        // After the target application connects, the sequence of actions is identical to the CONNECT command.
        tcp_acceptor_bind_.async_accept(
            tcp_socket_application_,
            [this, self = shared_from_this()](const error_code& ecode)
            {
              error_code ecode_ignore;
              tcp_acceptor_bind_.close(ecode_ignore);

              if (ecode) {
                DoSendReplyAndDeleteSession_(
                    ReplyCode::kRefused, kEmptyTcpEndpoint, log_level::error,
                    (boost::format("Failed to accept incoming connection: %s.") % ecode.message())
                        .str());
              } else {
                LogMessage(log_level::info,
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
              }
            });
      });
}

void Socks5Session::DoUdpAssociateCommand_() {
  auto addr_type =
      static_cast<AddressType>(reinterpret_cast<const TcpMessage*>(buffer_.data())->address_type) ==
              AddressType::kIPv6
          ? net_udp::v6()
          : net_udp::v4();

  // A UDP association terminates when the TCP connection that the UDP
  // ASSOCIATE request arrived at terminates.
  WaitForCloseTCPConnection(tcp_socket_client_);

  udp_socket_.open(addr_type);
  udp_socket_.bind(net_udp::endpoint(addr_type, 0));
  DoSendReply_(ReplyCode::kOk, udp_socket_.local_endpoint(),
               [this, self = shared_from_this()]()
               {
                 buffer_.resize(kUdpBufferSize);
                 LogMessage(log_level::info, "Running the UDP-ASSOCIATE command.");
                 DoTunnelingUdpTraffic_();
               });
}

void Socks5Session::DoTunnelingUdpTraffic_() {
  // When a UDP relay server decides to relay a UDP datagram, it does so silently, without
  // any notification to the requesting client. Similarly, it will drop datagrams it cannot
  // or will not relay.
  udp_socket_.async_receive_from(
      boost::asio::buffer(buffer_, buffer_.size()), udp_endpoint_application_,
      [this, self = shared_from_this()](const error_code& ecode, size_t readed_size)
      {
        if (ecode) {
          LogMessage(
              log_level::warning,
              (boost::format("Failed to receive data from UDP socket: %s.") % ecode.message())
                  .str());
        } else {
          // We need to get the sender address for the first message, since the sender of the first
          // message is the client.
          if (udp_endpoint_client_ == net_udp::endpoint(udp_endpoint_client_.protocol(), 0)) {
            udp_endpoint_client_ = udp_endpoint_application_;
          }

          if (udp_endpoint_client_ == udp_endpoint_application_) {  // Process incoming message
                                                                    // from client.
            DoResolveAddress_<UdpMessage, net_udp::resolver, net_udp::endpoint>(
                [this, self, readed_size](const error_code& ecode,
                                          const net_udp::endpoint& endpoint)
                {
                  if (ecode) {
                    LogMessage(
                        log_level::warning,
                        (boost::format("Domain name resolution error from UDP message: %s.") %
                         ecode)
                            .str());
                  } else {
                    // Calculating offset to data in buffer.
                    size_t offset_to_data = sizeof(UdpMessage);
                    if (endpoint.address().is_v4()) {
                      offset_to_data += sizeof(AddressV4);
                    } else {
                      offset_to_data += sizeof(AddressV6);
                    }

                    // Sending data to application.
                    udp_socket_.async_send_to(
                        boost::asio::buffer(buffer_.data() + offset_to_data,
                                            readed_size - offset_to_data),
                        endpoint,
                        [this, self](const error_code& ecode, size_t)
                        {
                          if (ecode) {
                            LogMessage(
                                log_level::warning,
                                (boost::format("Error sending UDP message: %s.") % ecode.message())
                                    .str());
                          } else {
                            DoTunnelingUdpTraffic_();
                          }
                        });
                  }
                });

          } else {  // Process incoming message from application.
            auto message = CreateUdpMessage(udp_endpoint_client_);

            // Adding received data to response.
            message->insert(message->end(), buffer_.begin(), buffer_.begin() + readed_size);

            // Sending response to client.
            udp_socket_.async_send_to(
                boost::asio::buffer(*message), udp_endpoint_client_,
                [this, self, message](const error_code& ecode, size_t)
                {
                  if (ecode) {
                    LogMessage(
                        log_level::warning,
                        (boost::format("Error sending UDP message: %s.") % ecode.message()).str());
                  } else {
                    DoTunnelingUdpTraffic_();
                  }
                });
          }
        }
      });
}

void Socks5Session::WaitForCloseTCPConnection(net_tcp::socket& socket) {
  char dummy;
  socket.async_read_some(boost::asio::buffer(&dummy, sizeof(dummy)),
                         [this, self = shared_from_this(), &socket](const error_code& ecode, size_t)
                         {
                           if (ecode) {
                             DeleteSession(log_level::info, "TCP connection was closed.");
                           } else {
                             WaitForCloseTCPConnection(socket);
                           }
                         });
}

}  // namespace session::socks5