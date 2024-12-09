#ifndef __COMMON_HPP__
#define __COMMON_HPP__

#include <cinttypes>
#include <ostream>
#include <string>

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

std::ostream &operator<<(std::ostream &os, const DNSPacket &packet);

struct TLSPacket {
  std::string shost;
  std::string dhost;

  std::string ip_src;
  std::string ip_dst;

  uint16_t sport;
  uint16_t dport;

  TLS tls;
};

std::ostream &operator<<(std::ostream &os, const TLSPacket &packet);

#endif /* __COMMON_HPP__ */
