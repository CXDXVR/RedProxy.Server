#include <boost/asio/signal_set.hpp>
#include "Common/Logger.h"
#include "Configuration.h"
#include "Server.h"

using namespace boost;

static std::shared_ptr<Server> CreateAndStartServer(asio::io_context& io_context,
                                                    Server::Version version) {
  auto config = Configuration::GetInstance();
  if (!config->IsLoaded()) {
    config->Load();
  }

  if ((version == Server::Version::kSocks4 && config->GetSocks4().enable) ||
      (version == Server::Version::kSocks5 && config->GetSocks5().enable)) {
    net_tcp::endpoint endpoint;

    endpoint.address(asio::ip::address::from_string(version == Server::Version::kSocks4
                                                        ? config->GetSocks4().address
                                                        : config->GetSocks5().address));
    endpoint.port(version == Server::Version::kSocks4 ? config->GetSocks4().port
                                                      : config->GetSocks5().port);

    auto server = Server::Create(io_context, endpoint, version);
    server->Start();
    if (server->IsOpen()) {
      WLOGGER(info) << (version == Server::Version::kSocks4 ? "SOCKS4" : "SOCKS5") << " running at "
                    << endpoint.address().to_string() << ":" << endpoint.port() << ".";
    } else {
      WLOGGER(error) << (version == Server::Version::kSocks4 ? "SOCKS4" : "SOCKS5")
                     << " was not running.";
    }
  } else {
    WLOGGER(info) << (version == Server::Version::kSocks4 ? "SOCKS4" : "SOCKS5")
                  << " disabled in configuration.";
  }

  return nullptr;
}

int main(int argc, char** argv) {
  asio::io_context context;
  asio::signal_set signal{context, SIGINT, SIGTERM};

  auto socks4 = CreateAndStartServer(context, Server::Version::kSocks4);
  auto socks5 = CreateAndStartServer(context, Server::Version::kSocks5);

  signal.async_wait([&context](auto, auto) { context.stop(); });
  context.run();

  return 0;
}