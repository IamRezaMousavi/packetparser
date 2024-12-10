#ifndef __TLS_HPP__
#define __TLS_HPP__

#include <cinttypes>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

enum TLSContentType {
  TLS_CTYPE_ALERT = 21,            // Alert message
  TLS_CTYPE_HANDSHAKE = 22,        // Handshake message
  TLS_CTYPE_APPLICATION_DATA = 23, // Application data message
  TLS_CTYPE_HEARTBEAT = 24,        // Heartbeat message
  TLS_CTYPE_CID = 25,
  TLS_CTYPE_ACK = 26,
  TLS_CTYPE_RTC = 27,
};

enum TLSVersion {
  SSL_3_0 = 0x0300, // SSL 3.0
  TLS_1_0 = 0x0301, // TLS 1.0
  TLS_1_1 = 0x0302, // TLS 1.1
  TLS_1_2 = 0x0303, // TLS 1.2
  TLS_1_3 = 0x0304, // TLS 1.3
};

enum TLSHandshakeType {
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

enum TLSExtensionType {
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
  uint16_t type;
  uint16_t len;

  TLSExtensionServerName servername;
};

struct TLSHandshake {
  uint8_t type;
  uint32_t len;
  uint16_t version;

  std::vector<uint8_t> random;

  TLSTuple sessionId;

  /* client hello */
  TLSTuple cipherSuits;
  TLSTuple compressionMethods;

  uint16_t extensionsLen;
  std::vector<TLSExtension> extensions;
};

struct TLS {
  uint8_t contentType;
  uint16_t version;
  uint32_t len;

  std::optional<TLSHandshake> handshake; // Optional handshake data (if contentType is HANDSHAKE)
};

struct TLSPacket {
  std::string shost;
  std::string dhost;

  std::string ip_src;
  std::string ip_dst;

  uint16_t sport;
  uint16_t dport;

  TLS tls;
};

void parseTLSExtensions(const u_char *data, TLSHandshake &tlsHandshake);

void parseTLSClientHello(const u_char *data, TLSHandshake &tlsHandshake);

TLS parseTLS(const u_char *data);

const char *TLSContentTypeToString(TLSContentType contentType);

const char *TLSVersionToString(TLSVersion version);

const char *TLSHandshakeTypeToString(TLSHandshakeType type);

const char *TLSExtensionTypeToString(TLSExtensionType type);

std::ostream &operator<<(std::ostream &os, const TLS &packet);

std::ostream &operator<<(std::ostream &os, const TLSPacket &packet);

#endif /* __TLS_HPP__ */
