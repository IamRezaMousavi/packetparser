#include "dns.hpp"

std::string parseDNSQueryName(const u_char *data, int &offset) {
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

DNSQuery parseDNSQuery(const u_char *data, int &offset) {
  DNSQuery query;
  query.name = parseDNSQueryName(data, offset);
  query.type = ntohs(*(uint16_t *)(data + offset));
  offset += 2;
  query.qclass = ntohs(*(uint16_t *)(data + offset));
  offset += 2;
  return query;
}

DNS parseDNS(const u_char *data) {
  DNS packet;
  int offset = 0;

  const DNSHeader *dnsHeader = (DNSHeader *)data;
  packet.transactionId = ntohs(dnsHeader->transactionId);
  packet.flags = ntohs(dnsHeader->flags);
  packet.queriesCount = ntohs(dnsHeader->q_count);
  packet.answersCount = ntohs(dnsHeader->and_count);
  packet.authoritiesCount = ntohs(dnsHeader->auth_count);
  packet.additionalsCount = ntohs(dnsHeader->add_count);

  offset += sizeof(DNSHeader);
  for (int i = 0; i < packet.queriesCount; ++i) {
    packet.queries.push_back(parseDNSQuery(data, offset));
  }

  return packet;
}

std::string QTypeToString(QType type) {
  switch (type) {
  case QTYPE_A:
    return "A";
  case QTYPE_NS:
    return "NS";
  case QTYPE_CNAME:
    return "CNAME";
  case QTYPE_SOA:
    return "SOA";
  case QTYPE_PTR:
    return "PTR";
  case QTYPE_MX:
    return "MX";
  case QTYPE_TXT:
    return "TXT";
  case QTYPE_AAAA:
    return "AAAA";
  case QTYPE_SRV:
    return "SRV";
  case QTYPE_ANY:
    return "ANY";
  default:
    return "Unknown";
  }
}

std::string QClassToString(QClass qclass) {
  switch (qclass) {
  case QCLASS_IN:
    return "IN";
  case QCLASS_CS:
    return "CS";
  case QCLASS_CH:
    return "CH";
  case QCLASS_HS:
    return "HS";
  case QCLASS_ANY:
    return "ANY";
  default:
    return "Unknown";
  }
}

std::ostream &operator<<(std::ostream &os, const DNSQuery &query) {
  os << "+------------------+-------------------+" << std::endl;
  os << "|       Query Name | " << query.name << std::endl;
  os << "|       Query Type | " << std::left << std::setw(17) << QTypeToString((QType)query.type) << " |" << std::endl;
  os << "|      Query Class | " << std::left << std::setw(17) << QClassToString((QClass)query.qclass) << " |"
     << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  return os;
}

std::ostream &operator<<(std::ostream &os, const DNS &packet) {
  os << "|                 DNS                  |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|   Transaction ID | 0x" << std::left << std::setw(15) << std::hex << packet.transactionId << std::dec << " |"
     << std::endl;
  os << "|            Flags | 0x" << std::left << std::setw(15) << std::hex << packet.flags << std::dec << " |"
     << std::endl;
  os << "|        Questions | " << std::left << std::setw(17) << packet.queriesCount << " |" << std::endl;
  os << "|       Answer PRs | " << std::left << std::setw(17) << packet.answersCount << " |" << std::endl;
  os << "|    Authority PRs | " << std::left << std::setw(17) << packet.authoritiesCount << " |" << std::endl;
  os << "|   Additional PRs | " << std::left << std::setw(17) << packet.additionalsCount << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|               Queries                |" << std::endl;
  for (const auto &query : packet.queries) {
    os << query;
  }

  return os;
}

std::ostream &operator<<(std::ostream &os, const DNSPacket &packet) {
  os << std::endl << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "|              DNS Packet              |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source MAC       | " << std::left << std::setw(17) << packet.shost << " |" << std::endl;
  os << "| Dest MAC         | " << std::left << std::setw(17) << packet.dhost << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source IP        | " << std::left << std::setw(17) << packet.ip_src << " |" << std::endl;
  os << "| Dest IP          | " << std::left << std::setw(17) << packet.ip_dst << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;
  os << "| Source Port      | " << std::left << std::setw(17) << packet.sport << " |" << std::endl;
  os << "| Dest Port        | " << std::left << std::setw(17) << packet.dport << " |" << std::endl;
  os << "+------------------+-------------------+" << std::endl;

  os << packet.dns;
  os << std::endl << std::endl;

  return os;
}
