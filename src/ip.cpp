#include "ip.hpp"

#include <arpa/inet.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

IP::IP(std::span<const uint8_t> data) {
  constexpr size_t MIN_HEADER_SIZE = 20;

  if (data.size() < MIN_HEADER_SIZE) {
    throw std::invalid_argument("IPv4 header is too short");
  }

  const struct ip *iphdr = (const struct ip *)data.data();
  ihl                    = iphdr->ip_hl * 4;

  if (ihl < MIN_HEADER_SIZE || data.size() < ihl) {
    throw std::invalid_argument("Invalid IPv4 header length");
  }

  src      = iphdr->ip_src;
  dst      = iphdr->ip_dst;
  protocol = iphdr->ip_p;
}

size_t IP::size() const { return ihl; }

std::unique_ptr<Layer> IP::clone() const { return std::make_unique<IP>(*this); }

std::string IP::toString() const {
  std::ostringstream ss;
  ss << "|                  IP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source IP        | " << std::left << std::setw(17) << inet_ntoa(src) << " |\n";
  ss << "| Dest IP          | " << std::left << std::setw(17) << inet_ntoa(dst) << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}
