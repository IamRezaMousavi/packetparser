#include "ether.hpp"

#include <arpa/inet.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

Ether::Ether(std::span<const uint8_t> data) {
  constexpr size_t HEADER_SIZE = sizeof(struct ether_header);

  if (data.size() < HEADER_SIZE) {
    throw std::invalid_argument("Ethernet header is too short");
  }

  const struct ether_header *eth = (const struct ether_header *)data.data();
  shost                          = *((struct ether_addr *)eth->ether_shost);
  dhost                          = *((struct ether_addr *)eth->ether_dhost);
  eth_type                       = ntohs(eth->ether_type);
}

size_t Ether::size() const { return sizeof(struct ether_header); }

std::unique_ptr<Layer> Ether::clone() const { return std::make_unique<Ether>(*this); }

std::string Ether::toString() const {
  std::ostringstream ss;
  ss << "+------------------+-------------------+\n";
  ss << "|               Ethernet               |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source MAC       | " << std::left << std::setw(17) << ether_ntoa(&shost) << " |\n";
  ss << "| Dest MAC         | " << std::left << std::setw(17) << ether_ntoa(&dhost) << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}
