#include "tls.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

// ---------- helpers ----------
namespace {

uint16_t readUint16(std::span<const uint8_t> data, size_t offset) {
  if (offset + 2 > data.size())
    throw std::runtime_error("TLS: not enough data for uint16");
  return (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
}

uint32_t readUint24(std::span<const uint8_t> data, size_t offset) {
  if (offset + 3 > data.size())
    throw std::runtime_error("TLS: not enough data for uint24");
  return (static_cast<uint32_t>(data[offset]) << 16) | (static_cast<uint32_t>(data[offset + 1]) << 8)
         | static_cast<uint32_t>(data[offset + 2]);
}

std::vector<uint8_t> readBytes(std::span<const uint8_t> data, size_t offset, size_t len) {
  if (offset + len > data.size())
    throw std::runtime_error("TLS: not enough data for bytes");
  return {data.begin() + offset, data.begin() + offset + len};
}

} // namespace

TLS::TLS(std::span<const uint8_t> data) {
  if (data.size() < 5)
    throw std::runtime_error("TLS: record too short");

  contentType = static_cast<TLSContentType>(data[0]);
  version     = static_cast<TLSVersion>(readUint16(data, 1));
  length      = readUint16(data, 3);

  if (contentType != TLSContentType::Handshake)
    return;

  if (data.size() < 9)
    throw std::runtime_error("TLS: handshake header too short");

  TLSHandshake hs;
  hs.type   = static_cast<TLSHandshakeType>(data[5]);
  hs.length = readUint24(data, 6);

  if (hs.type == TLSHandshakeType::ClientHello)
    hs.parseClientHello(data.subspan(9));

  handshake = std::move(hs);
}

size_t TLS::size() const { return length + 5; }

std::unique_ptr<Layer> TLS::clone() const { return std::make_unique<TLS>(*this); }

void TLSHandshake::parseClientHello(std::span<const uint8_t> data) {
  size_t offset = 0;

  version = readUint16(data, offset);
  offset += 2;

  random = readBytes(data, offset, 32);
  offset += 32;

  // Session ID
  sessionId.name = "session_id";
  sessionId.len  = data[offset++];
  sessionId.data = readBytes(data, offset, sessionId.len);
  offset += sessionId.len;

  // Cipher Suites
  cipherSuites.name = "cipher_suites";
  cipherSuites.len  = readUint16(data, offset);
  offset += 2;
  cipherSuites.data = readBytes(data, offset, cipherSuites.len);
  offset += cipherSuites.len;

  // Compression Methods
  compressionMethods.name = "compression_methods";
  compressionMethods.len  = data[offset++];
  compressionMethods.data = readBytes(data, offset, compressionMethods.len);
  offset += compressionMethods.len;

  // Extensions
  extensionsLen = readUint16(data, offset);
  offset += 2;

  if (extensionsLen != data.size() - offset) {
    throw std::runtime_error("TLS: invalid extensions length");
  }

  parseExtensions(data.subspan(offset, extensionsLen));
}

void TLSHandshake::parseExtensions(std::span<const uint8_t> data) {
  size_t offset = 0;

  while (offset < data.size()) {
    if (data.size() - offset < 4) {
      throw std::runtime_error("TLS: incomplete extension header");
    }

    TLSExtension ext;
    ext.type = static_cast<TLSExtensionType>(readUint16(data, offset));
    offset += 2;

    ext.len = readUint16(data, offset);
    offset += 2;

    if (ext.len > data.size() - offset) {
      throw std::runtime_error("TLS: extension data out of bounds");
    }

    const auto ext_data = data.subspan(offset, ext.len);

    if (ext.type == TLSExtensionType::ServerName && ext.len >= 5) {
      TLSExtensionServerName servername;

      servername.listLen = readUint16(ext_data, 0);

      if (servername.listLen > ext_data.size() - 2) {
        throw std::runtime_error("TLS: server name list out of bounds");
      }

      if (servername.listLen >= 3) {
        servername.type = ext_data[2];
        servername.len  = readUint16(ext_data, 3);

        if (servername.len > servername.listLen - 3) {
          throw std::runtime_error("TLS: server name out of bounds");
        }

        if (servername.type == 0) {
          servername.name.assign(reinterpret_cast<const char *>(ext_data.data() + 5), servername.len);
        }
      }

      ext.servername = std::move(servername);
    }

    extensions.push_back(std::move(ext));
    offset += ext.len;
  }
}

static std::string toString(const TLSContentType contentType) {
  switch (contentType) {
  case TLSContentType::Alert:
    return "Alert";
  case TLSContentType::Handshake:
    return "Handshake";
  case TLSContentType::ApplicationData:
    return "ApplicationData";
  case TLSContentType::Heartbeat:
    return "Heartbeat";
  default:
    return "Unknown";
  }
}

static std::string toString(const TLSVersion version) {
  switch (version) {
  case TLSVersion::TLS_1_0:
    return "TLS 1.0";
  case TLSVersion::TLS_1_1:
    return "TLS 1.1";
  case TLSVersion::TLS_1_2:
    return "TLS 1.2";
  case TLSVersion::TLS_1_3:
    return "TLS 1.3";
  default:
    return "UNKNOWN";
  }
}

static std::string toString(const TLSHandshakeType type) {
  switch (type) {
  case TLSHandshakeType::HelloRequest:
    return "Hello Request";
  case TLSHandshakeType::ClientHello:
    return "Client Hello";
  case TLSHandshakeType::ServerHello:
    return "Server Hello";
  case TLSHandshakeType::NewSessionTicket:
    return "New Ticket";
  case TLSHandshakeType::EndOfEarlyData:
    return "End Of Early Data";
  case TLSHandshakeType::Certificate:
    return "Certidicate";
  case TLSHandshakeType::ServerKeyExchange:
    return "Server Key Exchange";
  case TLSHandshakeType::ServerHelloDone:
    return "Server Hello Done";
  case TLSHandshakeType::CertificateRequest:
    return "Certificate Request";
  case TLSHandshakeType::ClientKeyExchange:
    return "Client Key Exchange";
  case TLSHandshakeType::Finished:
    return "Finished";
  case TLSHandshakeType::CertificateStatus:
    return "Certification Status";
  default:
    return "UNKNOWN";
  }
}

static std::string toString(const TLSExtensionType type) {
  switch (type) {
  case TLSExtensionType::ServerName:
    return "Server Name";
  case TLSExtensionType::SupportedVersions:
    return "Supported Versions";
  case TLSExtensionType::Padding:
    return "Padding";
  default:
    return "UNKNOWN";
  }
}

std::string TLS::toString() const {
  std::ostringstream ss;
  ss << "|                 TLS                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|     Content Type | " << std::left << std::setw(17) << ::toString(contentType) << " |\n";
  ss << "|          Version | " << std::left << std::setw(17) << ::toString(version) << " |\n";
  ss << "|           Length | " << std::left << std::setw(17) << length << " |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|              Handshake               |\n";
  ss << "+------------------+-------------------+\n";
  // If the packet contains handshake data, output it
  if (handshake.has_value()) {
    const auto &_handshake = handshake.value();
    ss << "|   Handshake Type | " << std::left << std::setw(17) << ::toString(_handshake.type) << " |\n";
    ss << "| Handshake Length | " << std::left << std::setw(17) << _handshake.length << " |\n";
    ss << "+------------------+-------------------+\n";

    if (!_handshake.extensions.empty()) {
      ss << "+------------------+-------------------+\n";
      ss << "|             Extensions               |\n";
      ss << "+------------------+-------------------+\n";
    }
    for (const auto &ext : _handshake.extensions) {
      if (ext.type != TLSExtensionType::ServerName && ext.type != TLSExtensionType::Padding
          && ext.type != TLSExtensionType::SupportedVersions)
        continue;

      ss << "|             Type | " << std::left << std::setw(17) << ::toString(ext.type) << " |\n";
      if (ext.servername.has_value())
        ss << "|     SNI Hostname | " << ext.servername.value().name << '\n';
      ss << "+------------------+-------------------+\n";
    }
  }

  return ss.str();
}

std::ostream &operator<<(std::ostream &os, const TLS &tls) {
  os << tls.toString();
  return os;
}
