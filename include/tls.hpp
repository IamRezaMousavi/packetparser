#ifndef TLS_HPP
#define TLS_HPP

#include <optional>
#include <span>
#include <vector>

#include "layer.hpp"

enum class TLSContentType : uint8_t {
  Alert           = 21, // Alert message
  Handshake       = 22, // Handshake message
  ApplicationData = 23, // Application data message
  Heartbeat       = 24, // Heartbeat message
  CID             = 25,
  ACK             = 26,
  RTC             = 27,
};

enum class TLSVersion : uint16_t {
  SSL_3_0 = 0x0300, // SSL 3.0
  TLS_1_0 = 0x0301, // TLS 1.0
  TLS_1_1 = 0x0302, // TLS 1.1
  TLS_1_2 = 0x0303, // TLS 1.2
  TLS_1_3 = 0x0304, // TLS 1.3
};

enum class TLSHandshakeType : uint8_t {
  HelloRequest       = 0,
  ClientHello        = 1,
  ServerHello        = 2,
  NewSessionTicket   = 4,
  EndOfEarlyData     = 5,
  Certificate        = 11,
  ServerKeyExchange  = 12,
  CertificateRequest = 13,
  ServerHelloDone    = 14,
  ClientKeyExchange  = 16,
  Finished           = 20,
  CertificateStatus  = 22,
};

enum class TLSExtensionType : uint16_t {
  ServerName        = 0,
  Padding           = 21,
  SupportedVersions = 43,
};

struct TLSTuple {
  std::string          name;
  uint16_t             len = 0;
  std::vector<uint8_t> data;
};

struct TLSExtensionServerName {
  uint16_t    listLen = 0;
  uint8_t     type    = 0;
  uint16_t    len     = 0;
  std::string name;
};

struct TLSExtension {
  TLSExtensionType                      type = TLSExtensionType::ServerName;
  uint16_t                              len  = 0;
  std::optional<TLSExtensionServerName> servername;
};

class TLSHandshake {
public:
  TLSHandshakeType type    = TLSHandshakeType::ClientHello;
  uint32_t         length  = 0;
  uint16_t         version = 0;

  std::vector<uint8_t> random;
  TLSTuple             sessionId;
  TLSTuple             cipherSuites;
  TLSTuple             compressionMethods;

  uint16_t                  extensionsLen = 0;
  std::vector<TLSExtension> extensions;

  void parseClientHello(std::span<const uint8_t> data);
  void parseExtensions(std::span<const uint8_t> data);
};

class TLS : public Layer {
public:
  TLSContentType contentType{};
  TLSVersion     version{};
  uint16_t       length = 0;

  std::optional<TLSHandshake> handshake;

  TLS() = default;
  explicit TLS(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

std::ostream &operator<<(std::ostream &os, const TLS &tls);

#endif /* TLS_HPP */
