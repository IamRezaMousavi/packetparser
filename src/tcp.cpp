#include "tcp.hpp"

#include <arpa/inet.h>
#include <iomanip>
#include <netinet/tcp.h>
#include <sstream>

TCP::TCP(const uint8_t *data, size_t totalLength) {
  const struct tcphdr *tcp = (const struct tcphdr *)data;
  sport = ntohs(tcp->th_sport);
  dport = ntohs(tcp->th_dport);

  payloadPtr = data + sizeof(struct tcphdr);
  payloadLen = totalLength > sizeof(struct tcphdr) ? totalLength - sizeof(struct tcphdr) : 0;
}

std::string TCP::toString() const {
  std::ostringstream ss;
  ss << "|                 TCP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source Port      | " << std::left << std::setw(17) << sport << " |\n";
  ss << "| Dest Port        | " << std::left << std::setw(17) << dport << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}

std::unique_ptr<Layer> TCP::clone() const { return std::make_unique<TCP>(*this); }
