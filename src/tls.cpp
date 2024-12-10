#include "tls.hpp"

void parseTLSExtensions(const u_char *data, TLSHandshake &tlsHandshake) {
  size_t offset = 0;
  for (size_t i = 0; i < tlsHandshake.extensionsLen; i++) {
    TLSExtension extension;
    extension.type = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    extension.len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (extension.type == TLS_EXT_SERVERNAME) {
      TLSExtensionServerName servername;
      servername.listLen = (data[offset] << 8) | data[offset + 1];
      offset += 2;
      servername.type = data[offset++];
      servername.len = (data[offset] << 8) | data[offset + 1];
      offset += 2;
      servername.name = std::string(data + offset, data + offset + servername.len);
      extension.servername = servername;
      tlsHandshake.extensions.push_back(extension);
      return;
    }
  }
}

void parseTLSClientHello(const u_char *data, TLSHandshake &tlsHandshake) {
  size_t offset = 0;
  tlsHandshake.version = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  tlsHandshake.random.assign(data + offset, data + offset + 32);
  offset += 32;

  tlsHandshake.sessionId.name = "session id";
  tlsHandshake.sessionId.len = data[offset++];
  tlsHandshake.sessionId.data.assign(data + offset, data + offset + tlsHandshake.sessionId.len);
  offset += tlsHandshake.sessionId.len;

  TLSTuple cipherSuits;
  cipherSuits.name = "cipher suits";
  cipherSuits.len = (data[offset] << 8) | data[offset + 1];
  offset += 2;
  cipherSuits.data.assign(data + offset, data + offset + cipherSuits.len);
  tlsHandshake.cipherSuits = cipherSuits;
  offset += cipherSuits.len;

  TLSTuple compressionMethods;
  compressionMethods.name = "compression methods";
  compressionMethods.len = data[offset++];
  compressionMethods.data.assign(data + offset, data + offset + compressionMethods.len);
  tlsHandshake.compressionMethods = compressionMethods;
  offset += compressionMethods.len;

  tlsHandshake.extensionsLen = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  parseTLSExtensions(data + offset, tlsHandshake);
}

TLS parseTLS(const u_char *data) {
  TLS packet;
  packet.contentType = data[0];
  packet.version = (data[1] << 8) | data[2];
  packet.len = (data[3] << 8) | data[4];

  if (packet.contentType == TLS_CTYPE_HANDSHAKE) {
    TLSHandshake handshake;
    const uint8_t *handshakeData = data + 5;
    handshake.type = handshakeData[0];
    handshake.len = (handshakeData[1] << 16) | (handshakeData[2] << 8) | handshakeData[3];

    switch (handshake.type) {
    case TLS_CLIENT_HELLO:
      parseTLSClientHello(data + 9, handshake);
      break;

    default:
      break;
    }

    packet.handshake = handshake;
  }

  return packet;
}

const char *TLSContentTypeToString(TLSContentType contentType) {
  switch (contentType) {
  case TLS_CTYPE_ALERT:
    return "Alert";
  case TLS_CTYPE_HANDSHAKE:
    return "Handshake";
  case TLS_CTYPE_APPLICATION_DATA:
    return "APPLICATION_DATA";
  case TLS_CTYPE_HEARTBEAT:
    return "HEARTBEAT";
  default:
    return "UNKNOWN";
  }
}

const char *TLSVersionToString(TLSVersion version) {
  switch (version) {
  case TLS_1_0:
    return "TLS 1.0";
  case TLS_1_1:
    return "TLS 1.1";
  case TLS_1_2:
    return "TLS 1.2";
  case TLS_1_3:
    return "TLS 1.3";
  default:
    return "UNKNOWN";
  }
}

const char *TLSHandshakeTypeToString(TLSHandshakeType type) {
  switch (type) {
  case TLS_HELLO_REQ:
    return "Hello Request";
  case TLS_CLIENT_HELLO:
    return "Client Hello";
  case TLS_SERVER_HELLO:
    return "Server Hello";
  case TLS_NEW_TICKET:
    return "New Ticket";
  case TLS_END_OF_EARLY_DATA:
    return "End Of Early Data";
  case TLS_CERT:
    return "Certidicate";
  case TLS_SERVER_KEY_EXCH:
    return "Server Key Exchange";
  case TLS_SERVER_HELLO_DONE:
    return "Server Hello Done";
  case TLS_CERT_REQ:
    return "Certificate Request";
  case TLS_CLIENT_KEY_EXCH:
    return "Client Key Exchange";
  case TLS_FINISHED:
    return "Finished";
  case TLS_CERT_STATUS:
    return "Certification Status";
  default:
    return "UNKNOWN";
  }
}

const char *TLSExtensionTypeToString(TLSExtensionType type) {
  switch (type) {
  case TLS_EXT_SERVERNAME:
    return "Server Name";
  case TLS_EXT_SUPPORTED_VERS:
    return "Supported Vers";
  case TLS_EXT_PADDING:
    return "Padding";
  default:
    return "UNKNOWN";
  }
}

std::ostream &operator<<(std::ostream &os, const TLS &packet) {
  os << "|                 TLS                  |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|     Content Type | " << std::left << std::setw(17)
     << TLSContentTypeToString((TLSContentType)packet.contentType) << " |" << std::endl;
  os << "|          Version | " << std::left << std::setw(17) << TLSVersionToString((TLSVersion)packet.version) << " |"
     << std::endl;
  os << "|           Length | " << std::left << std::setw(17) << packet.len << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|              Handshake               |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  // If the packet contains handshake data, output it
  if (packet.handshake.has_value()) {
    const auto &handshake = packet.handshake.value();
    os << "|   Handshake Type | " << std::left << std::setw(17)
       << TLSHandshakeTypeToString((TLSHandshakeType)handshake.type) << " |" << std::endl;
    os << "| Handshake Length | " << std::left << std::setw(17) << handshake.len << " |" << std::endl;
    os << "+------------------+-------------------+" << std::endl;

    if (!handshake.extensions.empty()) {
      os << "+------------------+-------------------+" << std::endl;
      os << "|             Extensions               |" << std::endl;
      os << "+------------------+-------------------+" << std::endl;
    }
    for (const auto &ext : handshake.extensions) {
      os << "|             Type | " << std::left << std::setw(17)
         << TLSExtensionTypeToString((TLSExtensionType)ext.type) << " |" << std::endl;
      os << "|     SNI Hostname | " << ext.servername.name << std::endl;
      os << "+------------------+-------------------+" << std::endl;
    }
  }

  return os;
}

std::ostream &operator<<(std::ostream &os, const TLSPacket &packet) {
  os << std::endl << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|              TLS Packet              |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source MAC       | " << std::left << std::setw(17) << packet.shost << " |" << std::endl;
  os << "| Dest MAC         | " << std::left << std::setw(17) << packet.dhost << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source IP        | " << std::left << std::setw(17) << packet.ip_src << " |" << std::endl;
  os << "| Dest IP          | " << std::left << std::setw(17) << packet.ip_dst << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source Port      | " << std::left << std::setw(17) << packet.sport << " |" << std::endl;
  os << "| Dest Port        | " << std::left << std::setw(17) << packet.dport << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;

  os << packet.tls;
  os << std::endl << std::endl;

  return os;
}
