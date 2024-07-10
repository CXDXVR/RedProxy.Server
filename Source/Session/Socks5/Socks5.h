#ifndef SESSION_SOCKS5_H_
#define SESSION_SOCKS5_H_

#include <boost/asio/write.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <vector>
#include "Common/AddressResolve.h"
#include "Session/AbstractSession.h"
#include "Session/Socks5/Socks5Types.h"

namespace session::socks5 {

class Socks5Session final : public AbstractSession {
  using Callback = std::function<void()>;

  Socks5Session(session_id id, const std::weak_ptr<Server>& server, net_tcp::socket&& socket);

 public:
  ~Socks5Session() = default;

  // Creates and returns an instance of the session.
  static std::shared_ptr<Socks5Session> Create(session_id id, const std::weak_ptr<Server>& server,
                                               net_tcp::socket&& socket);

  // Starting the session.
  void Start() override;

  // Stops the session, closes all connections.
  // After that, the session is no longer usable, regardless of calling Start again.
  void Stop() override;

 private:
  // The method of processing user authentication.
  // If successful, it passes control to the DoExecuteCommand_ method.
  void DoProcessAuthentication();

  // Processes the message received from the client and transfer control to a specific
  // command (CONNECT, BIND or UDP).
  // If successful, passes control to the DoConnectCommand_ or DoBindCommand_ or DoUdpAssociateCommand_ method.
  void DoExecuteCommand_();

  // CONNECT command handler.
  void DoConnectCommand();

  // BIND command handler.
  void DoBindCommand_();

  // UDP-ASSOCIATE command handler.
  void DoUdpAssociateCommand_();

  // Extracts and processes the target application address from the request.
  template <typename TMessage = TcpMessage, typename TResolver = net_tcp::resolver,
            typename TEndpoint = net_tcp::endpoint,
            typename TCallback = common::DomainResolverCallbackTCP>
  void DoResolveAddress_(TCallback callback);

  // Sends a response to the client, then passes control to the callback function.
  // In case of failure, deletes the current session without transferring control to the
  // callback function.
  template <typename TEndpoint>
  void DoSendReply_(ReplyCode code, const TEndpoint& endpoint, Callback callback);

  // Sends a response to the client and deletes the current session.
  // It has 2 optional parameters 'log_level' and 'message' for log output.
  // If the 'message' parameter is empty, the log will not be recorded.
  template <typename TEndpoint>
  void DoSendReplyAndDeleteSession_(ReplyCode code, const TEndpoint& endpoint,
                                    log_level level = log_level::info,
                                    const std::string& message = "");

  // Tunneling UDP traffic between udp_endpoint_client_ <-> udp_endpoint_application_
  // In case of an error, the function will not complete its work.
  void DoTunnelingUdpTraffic_();

  // Waits until the connection is closed on the specified TCP socket, then deletes the current session.
  // Used for the UDP-ASSOCIATE command.
  void WaitForCloseTCPConnection(net_tcp::socket& socket);

  std::vector<char> buffer_;
  net_tcp::socket tcp_socket_application_;
  net_tcp::acceptor tcp_acceptor_bind_;
  net_udp::socket udp_socket_;

  net_udp::endpoint udp_endpoint_client_;
  net_udp::endpoint udp_endpoint_application_;
};

template <typename TMessage, typename TResolver, typename TEndpoint, typename TCallback>
inline void Socks5Session::DoResolveAddress_(TCallback callback) {
  auto message = reinterpret_cast<const TMessage*>(buffer_.data());
  auto address_begin = buffer_.data() + sizeof(TMessage);

  switch (static_cast<AddressType>(message->address_type)) {
    case AddressType::kIPv4: {
      auto ipv4 = reinterpret_cast<const AddressV4*>(address_begin);
      callback({}, common::GetIPv4Endpoint<TEndpoint>(ipv4->address, ipv4->port));
      break;
    }
    case AddressType::kIPv6: {
      auto ipv6 = reinterpret_cast<AddressV6*>(address_begin);
      callback({}, common::GetIPv6Endpoint<TEndpoint>(ipv6->address, ipv6->port));
      break;
    }
    case AddressType::kDomainName: {
      auto domain = reinterpret_cast<const AddressDomain*>(address_begin);
      auto address = std::string(address_begin + sizeof(AddressDomain), domain->length);
      auto service = boost::endian::big_to_native(
          *reinterpret_cast<uint16_t*>(address_begin + sizeof(AddressDomain) + domain->length));

      common::ResolveDomainAddress<TResolver, TCallback>(tcp_socket_client_.get_executor(), address,
                                                         service, callback);
      break;
    }
    default:
      break;
  }
}

template <typename TEndpoint>
inline void Socks5Session::DoSendReply_(ReplyCode code, const TEndpoint& endpoint,
                                        Socks5Session::Callback callback) {
  auto message = std::make_shared<std::vector<char>>(sizeof(TcpMessage));
  auto raw_message = reinterpret_cast<TcpMessage*>(message->data());
  auto port = boost::endian::native_to_big(endpoint.port());

  raw_message->version = 0x5;
  raw_message->status = static_cast<uint8_t>(code);
  raw_message->reserved = 0x0;
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

  message->insert(message->end(), reinterpret_cast<uint8_t*>(&port),
                  reinterpret_cast<uint8_t*>(&port) + sizeof(port));

  boost::asio::async_write(
      tcp_socket_client_, boost::asio::buffer(*message),
      [this, self = shared_from_this(), callback, message](const error_code& ecode, size_t sended)
      {
        if (ecode) {
          DeleteSession(
              log_level::error,
              (boost::format("Error sending a response to the client: %s.") % ecode.message())
                  .str());
        } else {
          callback();
        }
      });
}

template <typename TEndpoint>
inline void Socks5Session::DoSendReplyAndDeleteSession_(ReplyCode code, const TEndpoint& endpoint,
                                                        log_level level,
                                                        const std::string& message) {
  DoSendReply_<TEndpoint>(code, endpoint,
                          [this, self = shared_from_this(), level, message]()
                          { DeleteSession(level, message); });
}

}  // namespace session::socks5

#endif  // !SESSION_SOCKS5_H_
