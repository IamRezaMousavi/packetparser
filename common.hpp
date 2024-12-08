#ifndef __COMMON_CPP__
#define __COMMON_CPP__

#include <string>
#include <cinttypes>
#include <ostream>

#include "dns.hpp"
#include "tls.hpp"

struct DNSPacket {
  std::string shost;
  std::string dhost;
  
  std::string ip_src;
  std::string ip_dst;

  uint16_t sport;
  uint16_t dport;

  DNS dns;
};

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

struct TLSPacket {
  std::string shost;
  std::string dhost;
  
  std::string ip_src;
  std::string ip_dst;

  uint16_t sport;
  uint16_t dport;

  TLS tls;
};

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

#endif /* __COMMON_CPP__ */
