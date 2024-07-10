#include "Configuration.h"
#include <fstream>

using namespace boost::program_options;

Configuration::Configuration() : is_loaded_{false}, socks4_config_{}, socks5_config_{} {}

std::shared_ptr<Configuration> Configuration::GetInstance() {
  static auto instance = std::shared_ptr<Configuration>(new Configuration);
  return instance;
}

void Configuration::Load() {
  std::ifstream config_file(kFileName);
  options_description options = CreateOptionsDescription();
  variables_map var_map;

  is_loaded_ = true;

  store(parse_config_file(config_file, options), var_map);
  notify(var_map);
}

bool Configuration::IsLoaded() const {
  return is_loaded_;
}

const Configuration::Socks4& Configuration::GetSocks4() const noexcept {
  return socks4_config_;
}

const Configuration::Socks5& Configuration::GetSocks5() const noexcept {
  return socks5_config_;
}

options_description Configuration::CreateOptionsDescription() {
  options_description options;

  // Socks4 options.
  {
    options.add_options()("socks4.enable",
                          value<bool>(&socks4_config_.enable)->default_value(true));
    options.add_options()("socks4.enable_connect",
                          value<bool>(&socks4_config_.enable_connect)->default_value(true));
    options.add_options()("socks4.enable_bind",
                          value<bool>(&socks4_config_.enable_bind)->default_value(true));
    options.add_options()("socks4.user_id",
                          value<std::string>(&socks4_config_.user_id)->default_value(""));
    options.add_options()("socks4.address",
                          value<std::string>(&socks4_config_.address)->default_value("127.0.0.1"));
    options.add_options()("socks4.port",
                          value<uint16_t>(&socks4_config_.port)->default_value(1080));
  }

  // Socks5 options.
  {
    options.add_options()("socks5.enable",
                          value<bool>(&socks5_config_.enable)->default_value(true));
    options.add_options()("socks5.enable_connect",
                          value<bool>(&socks5_config_.enable_connect)->default_value(true));
    options.add_options()("socks5.enable_bind",
                          value<bool>(&socks5_config_.enable_bind)->default_value(true));
    options.add_options()("socks5.enable_udp",
                          value<bool>(&socks5_config_.enable_udp)->default_value(true));
    options.add_options()("socks5.username",
                          value<std::string>(&socks5_config_.username)->default_value(""));
    options.add_options()("socks5.password",
                          value<std::string>(&socks5_config_.password)->default_value(""));
    options.add_options()("socks5.address",
                          value<std::string>(&socks5_config_.address)->default_value("127.0.0.1"));
    options.add_options()("socks5.port",
                          value<uint16_t>(&socks5_config_.port)->default_value(1081));
  }

  return options;
}
