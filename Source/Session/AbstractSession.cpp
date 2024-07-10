#include "Session/AbstractSession.h"
#include <boost/asio/write.hpp>
#include <boost/format.hpp>
#include "Common/Logger.h"
#include "Server.h"

namespace session {

AbstractSession::AbstractSession(session_id id, const std::weak_ptr<Server>& server,
                                 net_tcp::socket&& client_socket)
    : session_id_{id},
      tcp_socket_client_{std::move(client_socket)},
      config_{Configuration::GetInstance()},
      server_{server},
      tunneling_started_{false} {}

void AbstractSession::DoTunnelingTraffic(net_tcp::socket& source, net_tcp::socket& dest,
                                         boost::span<char> buffer) {
  tunneling_started_ = true;
  DoTunnelingReceive(source, dest, buffer);
  DoTunnelingReceive(dest, source, buffer);
}

void AbstractSession::DoTunnelingReceive(net_tcp::socket& source, net_tcp::socket& dest,
                                         boost::span<char> buffer) {
  source.async_read_some(
      boost::asio::buffer(buffer.data(), buffer.size()),
      [this, self = shared_from_this(), &source, &dest, buffer](const error_code& ecode,
                                                                size_t size)
      {
        if (ecode) {
          if (tunneling_started_) {
            tunneling_started_ = false;
            DeleteSession(ecode == boost::asio::error::eof ? log_level::info : log_level::error,
                          (boost::format("Error reading data: %s.") % ecode.message()).str());
          }
        } else {
          DoTunnelingSend(source, dest, buffer, size);
        }
      });
}

void AbstractSession::DoTunnelingSend(net_tcp::socket& source, net_tcp::socket& dest,
                                      boost::span<char> buffer, size_t size_to_send) {
  boost::asio::async_write(
      dest, boost::asio::buffer(buffer.data(), size_to_send),
      [this, self = shared_from_this(), &source, &dest, buffer](const error_code& ecode,
                                                                size_t size)
      {
        if (ecode) {
          if (tunneling_started_) {
            tunneling_started_ = false;
            DeleteSession(ecode == boost::asio::error::eof ? log_level::info : log_level::error,
                          (boost::format("Error sending data: %s.") % ecode.message()).str());
          }
        } else {
          DoTunnelingReceive(source, dest, buffer);
        }
      });
}

void AbstractSession::LogMessage(log_level level, const std::string& message) const {
  BOOST_LOG_STREAM_WITH_PARAMS(::boost::log::trivial::logger::get(),
                               (boost::log::keywords::severity = level))
      << "[" << session_id_ << "]: " << message;
}

void AbstractSession::DeleteSession(log_level level, const std::string& message) const {
  if (!message.empty()) {
    LogMessage(level, message);
  }

  if (auto lock = server_.lock()) {
    lock->DeleteSession(session_id_);
  }
}

}  // namespace session
