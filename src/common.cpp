#include "common.hpp"

std::ostream &operator<<(std::ostream &os, const DNSPacket &packet) {
  os << std::endl << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|              DNS Packet              |" << std::endl;
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

  os << packet.dns;
  os << std::endl << std::endl;

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
