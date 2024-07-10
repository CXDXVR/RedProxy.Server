#ifndef SESSIONS_SOCKS4_TYPES_H_
#define SESSIONS_SOCKS4_TYPES_H_

#include <cstdint>

namespace session::socks4 {

// Client requested command.
enum class Command : uint8_t { kConnect = 1, kBind = 2 };

// Reply status code.
enum class ReplyCode : uint8_t {
  kGranted = 90,           // Request granted.
  kRejected = 91,          // Request rejected or failed.
  kConnectionFailed = 92,  // Request rejected because SOCKS server cannot connect to
                          // ident on the client.
  kClientConflict = 93     // Request rejected because the client program and ident
                          // report different user - ids.
};

#pragma pack(push, 1)
// Request/reply message.
struct Message {
  uint8_t version;  // Socks version. Must be 0x4
  union {
    uint8_t command;  // Connection type. Must be one of the Command or ReplyCode.
    uint8_t status;   // Status type.
  };
  uint16_t port;     // Target port.
  uint32_t address;  // Target ip.
};
#pragma pack(pop)

}  // namespace session::socks4

#endif  // !SESSIONS_SOCKS4_TYPES_H_
