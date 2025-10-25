#include "dns.hpp"

#include <netinet/in.h>

#include <iomanip>
#include <sstream>

#include "utils.hpp"

std::string DNSQuery::parseDNSQueryName(const u_char *data, int &offset) {
  std::ostringstream name;
  while (data[offset] != 0) {
    int length = data[offset];
    offset++;
    if (!name.str().empty()) {
      name << ".";
    }
    name.write((const char *)(&data[offset]), length);
    offset += length;
  }
  offset++; // skip the null terminator
  return name.str();
}

DNSQuery::DNSQuery(const uint8_t *data, int &offset) {
  name  = parseDNSQueryName(data, offset);
  qtype = static_cast<QType>(ntohs(*(uint16_t *)(data + offset)));
  offset += 2;
  qclass = static_cast<QClass>(ntohs(*(uint16_t *)(data + offset)));
  offset += 2;
}

std::string DNSQuery::toString(QType type) const {
  switch (type) {
  case QType::A:
    return "A";
  case QType::NS:
    return "NS";
  case QType::CNAME:
    return "CNAME";
  case QType::SOA:
    return "SOA";
  case QType::PTR:
    return "PTR";
  case QType::MX:
    return "MX";
  case QType::TXT:
    return "TXT";
  case QType::AAAA:
    return "AAAA";
  case QType::SRV:
    return "SRV";
  case QType::ANY:
    return "ANY";
  default:
    return "Unknown";
  }
}

std::string DNSQuery::toString(QClass qclass) const {
  switch (qclass) {
  case QClass::IN:
    return "IN";
  case QClass::CS:
    return "CS";
  case QClass::CH:
    return "CH";
  case QClass::HS:
    return "HS";
  case QClass::ANY:
    return "ANY";
  default:
    return "Unknown";
  }
}

std::string DNSQuery::toString() const {
  std::ostringstream ss;
  ss << "+------------------+-------------------+\n";
  ss << "|       Query Name | " << name << '\n';
  ss << "|       Query Type | " << std::left << std::setw(17) << toString(qtype) << " |\n";
  ss << "|      Query Class | " << std::left << std::setw(17) << toString(qclass) << " |\n";
  ss << "+------------------+-------------------+\n";
  return ss.str();
}

struct DNSHeader {
  uint16_t transactionId;
  uint16_t flags;
  uint16_t q_count;
  uint16_t and_count;
  uint16_t auth_count;
  uint16_t add_count;
};

DNS::DNS(const uint8_t *data, size_t totalLength) {
  UNUSED(totalLength);

  const DNSHeader *dnsHeader = (DNSHeader *)data;
  transactionId              = ntohs(dnsHeader->transactionId);
  flags                      = ntohs(dnsHeader->flags);
  queriesCount               = ntohs(dnsHeader->q_count);
  answersCount               = ntohs(dnsHeader->and_count);
  authoritiesCount           = ntohs(dnsHeader->auth_count);
  additionalsCount           = ntohs(dnsHeader->add_count);

  int offset = sizeof(DNSHeader);
  for (int i = 0; i < queriesCount; ++i) {
    queries.push_back(DNSQuery(data, offset));
  }
}

std::unique_ptr<Layer> DNS::clone() const { return std::make_unique<DNS>(*this); }

std::string DNS::toString() const {
  std::ostringstream ss;
  ss << "|                 DNS                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|   Transaction ID | 0x" << std::left << std::setw(15) << std::hex << transactionId << std::dec << " |\n";
  ss << "|            Flags | 0x" << std::left << std::setw(15) << std::hex << flags << std::dec << " |\n";
  ss << "|        Questions | " << std::left << std::setw(17) << queriesCount << " |\n";
  ss << "|       Answer PRs | " << std::left << std::setw(17) << answersCount << " |\n";
  ss << "|    Authority PRs | " << std::left << std::setw(17) << authoritiesCount << " |\n";
  ss << "|   Additional PRs | " << std::left << std::setw(17) << additionalsCount << " |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|               Queries                |\n";
  for (const auto &query : queries) {
    ss << query.toString();
  }

  return ss.str();
}

std::ostream &operator<<(std::ostream &os, const DNS &dns) {
  os << dns.toString();
  return os;
}
