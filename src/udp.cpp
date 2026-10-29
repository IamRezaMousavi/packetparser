#include "udp.hpp"

#include <arpa/inet.h>
#include <netinet/udp.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

UDP::UDP(std::span<const uint8_t> data) {
  constexpr size_t HEADER_SIZE = sizeof(struct udphdr);

  if (data.size() < HEADER_SIZE) {
    throw std::invalid_argument("UDP header is too short");
  }

  const struct udphdr *udp = (const struct udphdr *)data.data();
  sport                    = ntohs(udp->uh_sport);
  dport                    = ntohs(udp->uh_dport);
}

size_t UDP::size() const { return sizeof(struct udphdr); }

std::unique_ptr<Layer> UDP::clone() const { return std::make_unique<UDP>(*this); }

std::string UDP::toString() const {
  std::ostringstream ss;
  ss << "|                 UDP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source Port      | " << std::left << std::setw(17) << sport << " |\n";
  ss << "| Dest Port        | " << std::left << std::setw(17) << dport << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}
