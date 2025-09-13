#include "ip.hpp"

#include <arpa/inet.h>
#include <iomanip>
#include <netinet/ip.h>
#include <sstream>

IP::IP(const uint8_t *data, size_t totalLength) {
  const struct ip *iphdr = (const struct ip *)data;
  src = inet_ntoa(iphdr->ip_src);
  dst = inet_ntoa(iphdr->ip_dst);
  protocol = iphdr->ip_p;
  ihl = iphdr->ip_hl * 4;

  payloadPtr = data + ihl;
  payloadLen = totalLength > ihl ? totalLength - ihl : 0;
}

std::string IP::toString() const {
  std::ostringstream ss;
  ss << "|                  IP                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "| Source IP        | " << std::left << std::setw(17) << src << " |\n";
  ss << "| Dest IP          | " << std::left << std::setw(17) << dst << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}

std::unique_ptr<Layer> IP::clone() const { return std::make_unique<IP>(*this); }
