#include "tcp.hpp"

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <iomanip>
#include <sstream>

TCP::TCP(std::span<const uint8_t> data) {
  constexpr size_t HEADER_SIZE = sizeof(struct tcphdr);

  if (data.size() < HEADER_SIZE) {
    throw std::invalid_argument("TCP header is too short");
  }

  const struct tcphdr *tcp = (const struct tcphdr *)data.data();
  thl                      = tcp->th_off * 4;

  if (thl < HEADER_SIZE || data.size() < thl) {
    throw std::invalid_argument("Invalid TCP header length");
  }

  sport = ntohs(tcp->th_sport);
  dport = ntohs(tcp->th_dport);
}

size_t TCP::size() const { return thl; }

std::unique_ptr<Layer> TCP::clone() const { return std::make_unique<TCP>(*this); }

std::string TCP::toString() const {
  std::ostringstream ss;
  ss << "|                 TCP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source Port      | " << std::left << std::setw(17) << sport << " |\n";
  ss << "| Dest Port        | " << std::left << std::setw(17) << dport << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}
