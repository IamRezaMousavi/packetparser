#include "udp.hpp"

#include <arpa/inet.h>
#include <netinet/udp.h>

#include <iomanip>
#include <sstream>

UDP::UDP(const uint8_t *data, size_t totalLength) {
  const struct udphdr *udp = (const struct udphdr *)data;
  sport                    = ntohs(udp->uh_sport);
  dport                    = ntohs(udp->uh_dport);

  payloadPtr = data + sizeof(struct udphdr);
  payloadLen = totalLength > sizeof(struct udphdr) ? totalLength - sizeof(struct udphdr) : 0;
}

std::string UDP::toString() const {
  std::ostringstream ss;
  ss << "|                 UDP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source Port      | " << std::left << std::setw(17) << sport << " |\n";
  ss << "| Dest Port        | " << std::left << std::setw(17) << dport << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}

std::unique_ptr<Layer> UDP::clone() const { return std::make_unique<UDP>(*this); }
