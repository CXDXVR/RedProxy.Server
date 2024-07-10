#ifndef SESSION_SOCKS5_TYPES_H_
#define SESSION_SOCKS5_TYPES_H_

#include <cstdint>

namespace session::socks5 {

enum class AuthenticationMethod : uint8_t {
  kNoAuth = 0x00,        // NO AUTHENTICATION REQUIRED
  kGSSAPI = 0x01,        // GSSAPI
  kUserPassword = 0x02,  // USERNAME/PASSWORD
  kIANA = 0x03,          // to X'7F' IANA ASSIGNED
  kPrivate = 0x80,       // to X'FE' RESERVED FOR PRIVATE METHODS
  kNoAcceptable = 0xFF,  // NO ACCEPTABLE METHODS
};

// Command types.
enum class Command : uint8_t { kConnect = 0x01, kBind = 0x02, kUdpAssociate = 0x03 };

enum class AddressType : uint8_t {
  kIPv4 = 0x1,
  kDomainName = 0x3,
  kIPv6 = 0x4,
};

// Reply codes.
enum class ReplyCode : uint8_t {
  kOk = 0x00,              // succeeded
  kError = 0x01,           // general SOCKS server failure
  kNotAllowed = 0x02,      // connection not allowed by ruleset
  kErrorNet = 0x03,        // Network unreachable
  kErrorHost = 0x04,       // Host unreachable
  kRefused = 0x05,         // Connection refused
  kTTL = 0x06,             // TTL expired
  kUnknownCommand = 0x07,  // Command not supported
  kUnknownAddress = 0x08,  // Address type not supported
  kUnknown = 0x09          // X'09' to X'FF' unassigned
};

#pragma pack(push, 1)

// Request/reply authentication message.
struct AuthenticationMessage {
  uint8_t version;  // Socks5 version.
  union {
    uint8_t count;   // Count of methods.
    uint8_t method;  // Selected method.
  };
};

// Request/reply TCP message.
struct TcpMessage {
  uint8_t version;  // Socks version.
  union {
    uint8_t status;   // Status code.
    uint8_t command;  // Command type.
  };
  uint8_t reserved;      // Reserved.
  uint8_t address_type;  // Address type ipv4/ipv6/domain.
};

// Request/reply UDP message.
struct UdpMessage {
  uint16_t reserved;    // Reserved X'0000'
  uint8_t fragment;     // Current fragment number
  uint8_t address_type;  // Address type Constants::Socks5::AddressType::*.
};

// Socks5 IPv4 address.
struct AddressV4 {
  uint32_t address;
  uint16_t port;
};

// IPv6 address.
struct AddressV6 {
  uint8_t address[16];
  uint16_t port;
};

// Domain name address.
struct AddressDomain {
  uint8_t length;
  //uint8_t name[256 + sizeof(uint16_t)/*port*/];
};

#pragma pack(pop)

}  // namespace session::socks5

#endif  // !SESSION_SOCKS5_TYPES_H_
