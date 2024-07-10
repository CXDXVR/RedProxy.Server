#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <boost/program_options.hpp>
#include <memory>
#include <string>

class Configuration {
 private:
  static constexpr char kFileName[] = "settings.ini";

  Configuration();

 public:
  struct Socks4 {
    bool enable;
    bool enable_connect;  // Enable CONNECT command.
    bool enable_bind;     // Enable BIND command.
    std::string user_id;  // USER-ID authentication
    std::string address;  // Address.
    uint16_t port;        // Port.
  };

  struct Socks5 {
    bool enable;
    bool enable_connect;   // Enable CONNECT command.
    bool enable_bind;      // Enable BIND command.
    bool enable_udp;       // Enable UDP-ASSOCIATE command.
    std::string username;  // Authentication username.
    std::string password;  // Authentication password.
    std::string address;   // Address.
    uint16_t port;         // Port.
  };

  ~Configuration() = default;

  // Returns an instance of the class
  static std::shared_ptr<Configuration> GetInstance();

  // Loads the configuration into memory
  void Load();

  // Returns true if the configuration has been loaded.
  bool IsLoaded() const;

  // Returns the socks4 configuration
  const Socks4& GetSocks4() const noexcept;
  // Returns the socks5 configuration.
  const Socks5& GetSocks5() const noexcept;

 private:
  // Initializes and returns options_description.
  boost::program_options::options_description CreateOptionsDescription();

  bool is_loaded_;
  Socks4 socks4_config_;
  Socks5 socks5_config_;
};

#endif  // !CONFIGURATION_H_
