#ifndef __TLS_HPP__
#define __TLS_HPP__

#include "layer.hpp"

#include <optional>

enum class TLSContentType : uint8_t {
  TLS_CTYPE_ALERT = 21,            // Alert message
  TLS_CTYPE_HANDSHAKE = 22,        // Handshake message
  TLS_CTYPE_APPLICATION_DATA = 23, // Application data message
  TLS_CTYPE_HEARTBEAT = 24,        // Heartbeat message
  TLS_CTYPE_CID = 25,
  TLS_CTYPE_ACK = 26,
  TLS_CTYPE_RTC = 27,
};

enum class TLSVersion : uint16_t {
  SSL_3_0 = 0x0300, // SSL 3.0
  TLS_1_0 = 0x0301, // TLS 1.0
  TLS_1_1 = 0x0302, // TLS 1.1
  TLS_1_2 = 0x0303, // TLS 1.2
  TLS_1_3 = 0x0304, // TLS 1.3
};

enum class TLSHandshakeType : uint8_t {
  TLS_HELLO_REQ = 0,
  TLS_CLIENT_HELLO = 1,
  TLS_SERVER_HELLO = 2,
  TLS_NEW_TICKET = 4,
  TLS_END_OF_EARLY_DATA = 5,
  TLS_CERT = 11,
  TLS_SERVER_KEY_EXCH = 12,
  TLS_SERVER_HELLO_DONE = 14,
  TLS_CERT_REQ = 13,
  TLS_CLIENT_KEY_EXCH = 16,
  TLS_FINISHED = 20,
  TLS_CERT_STATUS = 22,
};

enum class TLSExtensionType : uint16_t {
  TLS_EXT_SERVERNAME = 0,
  TLS_EXT_PADDING = 21,
  TLS_EXT_SUPPORTED_VERS = 43,
};

struct TLSTuple {
  std::string name;
  uint16_t len;
  std::vector<uint8_t> data;
};

struct TLSExtensionServerName {
  uint16_t listLen;
  uint8_t type;
  uint16_t len;
  std::string name;
};

struct TLSExtension {
public:
  TLSExtensionType type;
  uint16_t len;

  TLSExtensionServerName servername{};
  std::string toString(TLSExtensionType type) const;
};

class TLSHandshake {
public:
  void parseTLSClientHello(const u_char *data);
  void parseTLSExtensions(const u_char *data);
  TLSHandshakeType type;
  uint32_t len;
  uint16_t version;

  std::vector<uint8_t> random;

  TLSTuple sessionId;

  /* client hello */
  TLSTuple cipherSuits;
  TLSTuple compressionMethods;

  uint16_t extensionsLen;
  std::vector<TLSExtension> extensions;
  std::string toString(TLSHandshakeType type) const;
};

class TLS : public Layer {
public:
  TLSContentType contentType;
  TLSVersion version;
  uint32_t len;

  std::optional<TLSHandshake> handshake;

  TLS() = default;
  TLS(const TLS &) = default;
  TLS &operator=(const TLS &) = default;
  TLS(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;

private:
  std::string toString(TLSContentType contentType) const;
  std::string toString(TLSVersion version) const;
};

std::ostream &operator<<(std::ostream &os, const TLS &tls);

#endif /* __TLS_HPP__ */
