#include "tls.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "utils.hpp"

TLS::TLS(const uint8_t *data, size_t totalLength) {
  UNUSED(totalLength);

  contentType = static_cast<TLSContentType>(data[0]);
  version     = static_cast<TLSVersion>((data[1] << 8) | data[2]);
  len         = (data[3] << 8) | data[4];

  if (contentType == TLSContentType::TLS_CTYPE_HANDSHAKE) {
    const uint8_t *handshakeData = data + 5;
    TLSHandshake   handshake;
    handshake.type = static_cast<TLSHandshakeType>(handshakeData[0]);
    handshake.len  = (handshakeData[1] << 16) | (handshakeData[2] << 8) | handshakeData[3];

    switch (handshake.type) {
    case TLSHandshakeType::TLS_CLIENT_HELLO:
      handshake.parseTLSClientHello(data + 9);
      break;

    default:
      break;
    }

    handshake = handshake;
  }
}

void TLSHandshake::parseTLSClientHello(const uint8_t *data) {
  size_t offset = 0;
  version       = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  random.assign(data + offset, data + offset + 32);
  offset += 32;

  sessionId.name = "session id";
  sessionId.len  = data[offset++];
  sessionId.data.assign(data + offset, data + offset + sessionId.len);
  offset += sessionId.len;

  TLSTuple cipherSuits;
  cipherSuits.name = "cipher suits";
  cipherSuits.len  = (data[offset] << 8) | data[offset + 1];
  offset += 2;
  cipherSuits.data.assign(data + offset, data + offset + cipherSuits.len);
  cipherSuits = cipherSuits;
  offset += cipherSuits.len;

  TLSTuple compressionMethods;
  compressionMethods.name = "compression methods";
  compressionMethods.len  = data[offset++];
  compressionMethods.data.assign(data + offset, data + offset + compressionMethods.len);
  compressionMethods = compressionMethods;
  offset += compressionMethods.len;

  extensionsLen = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  parseTLSExtensions(data + offset);
}

void TLSHandshake::parseTLSExtensions(const uint8_t *data) {
  size_t offset = 0;
  for (size_t i = 0; i < extensionsLen; i++) {
    TLSExtension extension;
    extension.type = static_cast<TLSExtensionType>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    extension.len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (extension.type == TLSExtensionType::TLS_EXT_SERVERNAME) {
      TLSExtensionServerName servername;
      servername.listLen = (data[offset] << 8) | data[offset + 1];
      offset += 2;
      servername.type = data[offset++];
      servername.len  = (data[offset] << 8) | data[offset + 1];
      offset += 2;
      servername.name      = std::string(data + offset, data + offset + servername.len);
      extension.servername = servername;
      extensions.push_back(extension);
    }
  }
}

std::string TLS::toString(const TLSContentType contentType) const {
  switch (contentType) {
  case TLSContentType::TLS_CTYPE_ALERT:
    return "Alert";
  case TLSContentType::TLS_CTYPE_HANDSHAKE:
    return "Handshake";
  case TLSContentType::TLS_CTYPE_APPLICATION_DATA:
    return "APPLICATION_DATA";
  case TLSContentType::TLS_CTYPE_HEARTBEAT:
    return "HEARTBEAT";
  default:
    return "UNKNOWN";
  }
}

std::string TLS::toString(TLSVersion version) const {
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

std::string TLSHandshake::toString(TLSHandshakeType type) const {
  switch (type) {
  case TLSHandshakeType::TLS_HELLO_REQ:
    return "Hello Request";
  case TLSHandshakeType::TLS_CLIENT_HELLO:
    return "Client Hello";
  case TLSHandshakeType::TLS_SERVER_HELLO:
    return "Server Hello";
  case TLSHandshakeType::TLS_NEW_TICKET:
    return "New Ticket";
  case TLSHandshakeType::TLS_END_OF_EARLY_DATA:
    return "End Of Early Data";
  case TLSHandshakeType::TLS_CERT:
    return "Certidicate";
  case TLSHandshakeType::TLS_SERVER_KEY_EXCH:
    return "Server Key Exchange";
  case TLSHandshakeType::TLS_SERVER_HELLO_DONE:
    return "Server Hello Done";
  case TLSHandshakeType::TLS_CERT_REQ:
    return "Certificate Request";
  case TLSHandshakeType::TLS_CLIENT_KEY_EXCH:
    return "Client Key Exchange";
  case TLSHandshakeType::TLS_FINISHED:
    return "Finished";
  case TLSHandshakeType::TLS_CERT_STATUS:
    return "Certification Status";
  default:
    return "UNKNOWN";
  }
}

std::string TLSExtension::toString(TLSExtensionType type) const {
  switch (type) {
  case TLSExtensionType::TLS_EXT_SERVERNAME:
    return "Server Name";
  case TLSExtensionType::TLS_EXT_SUPPORTED_VERS:
    return "Supported Vers";
  case TLSExtensionType::TLS_EXT_PADDING:
    return "Padding";
  default:
    return "UNKNOWN";
  }
}

std::unique_ptr<Layer> TLS::clone() const { return std::make_unique<TLS>(*this); }

std::string TLS::toString() const {
  std::ostringstream ss;
  ss << "|                 TLS                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|     Content Type | " << std::left << std::setw(17) << toString(contentType) << " |\n";
  ss << "|          Version | " << std::left << std::setw(17) << toString(version) << " |\n";
  ss << "|           Length | " << std::left << std::setw(17) << len << " |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|              Handshake               |\n";
  ss << "+------------------+-------------------+\n";
  // If the packet contains handshake data, output it
  if (handshake.has_value()) {
    const auto &_handshake = handshake.value();
    ss << "|   Handshake Type | " << std::left << std::setw(17) << _handshake.toString(_handshake.type) << " |\n";
    ss << "| Handshake Length | " << std::left << std::setw(17) << _handshake.len << " |\n";
    ss << "+------------------+-------------------+\n";

    if (!_handshake.extensions.empty()) {
      ss << "+------------------+-------------------+\n";
      ss << "|             Extensions               |\n";
      ss << "+------------------+-------------------+\n";
    }
    for (const auto &ext : _handshake.extensions) {
      ss << "|             Type | " << std::left << std::setw(17) << ext.toString(ext.type) << " |\n";
      ss << "|     SNI Hostname | " << ext.servername.name << '\n';
      ss << "+------------------+-------------------+\n";
    }
  }

  return ss.str();
}

std::ostream &operator<<(std::ostream &os, const TLS &tls) {
  os << tls.toString();
  return os;
}
