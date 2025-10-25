#include "ether.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <iomanip>
#include <sstream>

Ether::Ether(const uint8_t *data, size_t totalLength) {
  const struct ether_header *eth = (const struct ether_header *)data;
  shost                          = ether_ntoa((struct ether_addr *)eth->ether_shost);
  dhost                          = ether_ntoa((struct ether_addr *)eth->ether_dhost);
  eth_type                       = ntohs(eth->ether_type);

  payloadPtr = data + sizeof(struct ether_header);
  payloadLen = totalLength > sizeof(struct ether_header) ? totalLength - sizeof(struct ether_header) : 0;
}

std::string Ether::toString() const {
  std::ostringstream ss;
  ss << "|               Ethernet               |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source MAC       | " << std::left << std::setw(17) << shost << " |\n";
  ss << "| Dest MAC         | " << std::left << std::setw(17) << dhost << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}

std::unique_ptr<Layer> Ether::clone() const { return std::make_unique<Ether>(*this); }
