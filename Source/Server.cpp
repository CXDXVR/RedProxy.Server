#include "Server.h"
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <limits>
#include "Common/Logger.h"
#include "Session/AbstractSession.h"
#include "Session/Socks4/Socks4.h"
#include "Session/Socks5/Socks5.h"

Server::Server(boost::asio::io_context& context, const net_tcp::endpoint& endpoint, Version version)
    : version_{version}, tcp_endpoint_{endpoint}, tcp_acceptor_{context}, sessions_{} {}

std::shared_ptr<Server> Server::Create(boost::asio::io_context& context,
                                       const net_tcp::endpoint& endpoint, Version version) {
  return std::shared_ptr<Server>(new Server(context, endpoint, version));
}

void Server::Start() {
  if (!IsOpen()) {
    tcp_acceptor_.open(tcp_endpoint_.protocol());
    tcp_acceptor_.bind(tcp_endpoint_);
    tcp_acceptor_.listen();
  }

  tcp_acceptor_.async_accept(
      [this, self = shared_from_this()](const error_code& ecode, net_tcp::socket socket)
      {
        if (ecode) {
          WLOGGER(error) << (boost::format("Failed to accept incoming connection: %d, %s.") %
                             ecode.value() % ecode.message())
                                .str();

        } else {
          if (auto index = GenerateSessionId(); index != session::AbstractSession::kInvalidId) {
            std::shared_ptr<session::AbstractSession> session;

            switch (version_) {
              case Version::kSocks4: {
                WLOGGER(info) << "Receiving an incoming SOCKS4 client.";
                session = session::socks4::Socks4Session::Create(index, shared_from_this(),
                                                                 std::move(socket));
                break;
              }
              case Version::kSocks5: {
                WLOGGER(info) << "Receiving an incoming SOCKS5 client.";
                session = session::socks5::Socks5Session::Create(index, shared_from_this(),
                                                                 std::move(socket));
                break;
              }
            }

            sessions_[index] = session;
            session->Start();
          } else {
            WLOGGER(info) << "Error generating the client's UID.";
          }

          Start();
        }
      });
}

void Server::Stop() {
  error_code ecode;
  tcp_acceptor_.close(ecode);

  for (size_t cx = 0; cx < sessions_.size(); cx++) {
    sessions_[cx]->Stop();
    DeleteSession(cx);
  }
}

bool Server::IsOpen() const {
  return tcp_acceptor_.is_open();
}

void Server::DeleteSession(session_id id) {
  sessions_.erase(id);
  BOOST_LOG_TRIVIAL(info) << boost::format("Session %d deleted.") % id;
}

Server::session_id Server::GenerateSessionId() {
  static session_id id = 0;
  static constexpr session_id limit = std::numeric_limits<session_id>::max();

  for (; id < limit; ++id) {
    if (sessions_.find(id) == sessions_.end()) {
      return id;
    }
  }

  return session::AbstractSession::kInvalidId;
}
