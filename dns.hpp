#ifndef __DNS_HPP__
#define __DNS_HPP__

#include <cinttypes>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <vector>

enum QType {
  QTYPE_A = 0x01,     // A
  QTYPE_NS = 0x02,    // NS
  QTYPE_CNAME = 0x05, // CNAME
  QTYPE_SOA = 0x06,   // SOA
  QTYPE_PTR = 0x0C,   // PTR
  QTYPE_MX = 0x0F,    // MX
  QTYPE_TXT = 0x10,   // TXT
  QTYPE_AAAA = 0x1C,  // AAAA
  QTYPE_SRV = 0x21,   // SRV
  QTYPE_ANY = 0xFF    // ANY
};

enum QClass {
  QCLASS_IN = 0x01, // IN
  QCLASS_CS = 0x02, // CS
  QCLASS_CH = 0x03, // CH
  QCLASS_HS = 0x04, // HS
  QCLASS_ANY = 0xFF // ANY
};

enum DNSFlags {
  QR_MASK = 0x8000,     // QR flag: 1-bit, Request or Response (QR)
  OPCODE_MASK = 0x7800, // Opcode: 4-bits
  AA_MASK = 0x0400,     // AA flag: 1-bit, Authoritative Answer
  TC_MASK = 0x0200,     // TC flag: 1-bit, Truncated
  RD_MASK = 0x0100,     // RD flag: 1-bit, Recursion Desired
  RA_MASK = 0x0080,     // RA flag: 1-bit, Recursion Available
  Z_MASK = 0x0040,      // Z flag: Reserved
  RCODE_MASK = 0x000F   // RCODE: 4-bits, Response Code
};

struct DNSHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t q_count;
  uint16_t and_count;
  uint16_t auth_count;
  uint16_t add_count;
};

struct DNSQuery {
  std::string name;
  uint16_t type;
  uint16_t qclass;
};

struct DNS {
  uint16_t id;
  uint16_t flags;

  uint16_t queriesCount;
  uint16_t answersCount;
  uint16_t authoritiesCount;
  uint16_t additionalsCount;

  std::vector<DNSQuery> queries;
};

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
  packet.id = ntohs(dnsHeader->id);
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

std::ostream &operator<<(std::ostream &os, const DNSQuery &query) {
  os << "    Query Name: " << query.name << std::endl;
  os << "    Query Type: ";
  switch (query.type) {
  case QTYPE_A:
    os << "A" << std::endl;
    break;
  case QTYPE_NS:
    os << "NS" << std::endl;
    break;
  case QTYPE_CNAME:
    os << "CNAME" << std::endl;
    break;
  case QTYPE_SOA:
    os << "SOA" << std::endl;
    break;
  case QTYPE_PTR:
    os << "PTR" << std::endl;
    break;
  case QTYPE_MX:
    os << "MX" << std::endl;
    break;
  case QTYPE_TXT:
    os << "TXT" << std::endl;
    break;
  case QTYPE_AAAA:
    os << "AAAA" << std::endl;
    break;
  case QTYPE_SRV:
    os << "SRV" << std::endl;
    break;
  case QTYPE_ANY:
    os << "ANY" << std::endl;
    break;
  default:
    os << "Unknown" << std::endl;
    break;
  }

  os << "    Query Class: ";
  switch (query.qclass) {
  case QCLASS_IN:
    os << "IN" << std::endl;
    break;
  case QCLASS_CS:
    os << "CS" << std::endl;
    break;
  case QCLASS_CH:
    os << "CH" << std::endl;
    break;
  case QCLASS_HS:
    os << "HS" << std::endl;
    break;
  case QCLASS_ANY:
    os << "ANY" << std::endl;
    break;
  default:
    os << "Unknown" << std::endl;
    break;
  }

  return os;
}

std::ostream &operator<<(std::ostream &os, const DNS &packet) {
  os << "DNS Packet:" << std::endl;
  os << "    Transaction ID: 0x" << std::hex << packet.id << std::dec << std::endl;
  os << "    Flags: 0x" << std::hex << packet.flags << std::dec << std::endl;
  os << "    Queries Count: " << packet.queriesCount << std::endl;
  os << "    Answers Count: " << packet.answersCount << std::endl;
  os << "    Authority Count: " << packet.authoritiesCount << std::endl;
  os << "    Additional Count: " << packet.additionalsCount << std::endl;

  for (const auto &query : packet.queries) {
    os << query;
  }

  return os;
}

#define IS_QTYPE_A(qtype) ((qtype) == QTYPE_A)
#define IS_QTYPE_NS(qtype) ((qtype) == QTYPE_NS)
#define IS_QTYPE_CNAME(qtype) ((qtype) == QTYPE_CNAME)
#define IS_QTYPE_SOA(qtype) ((qtype) == QTYPE_SOA)
#define IS_QTYPE_PTR(qtype) ((qtype) == QTYPE_PTR)
#define IS_QTYPE_MX(qtype) ((qtype) == QTYPE_MX)
#define IS_QTYPE_TXT(qtype) ((qtype) == QTYPE_TXT)
#define IS_QTYPE_AAAA(qtype) ((qtype) == QTYPE_AAAA)
#define IS_QTYPE_SRV(qtype) ((qtype) == QTYPE_SRV)
#define IS_QTYPE_ANY(qtype) ((qtype) == QTYPE_ANY)

#define IS_QCLASS_IN(qclass) ((qclass) == QCLASS_IN)
#define IS_QCLASS_CS(qclass) ((qclass) == QCLASS_CS)
#define IS_QCLASS_CH(qclass) ((qclass) == QCLASS_CH)
#define IS_QCLASS_HS(qclass) ((qclass) == QCLASS_HS)
#define IS_QCLASS_ANY(qclass) ((qclass) == QCLASS_ANY)

#define IS_QR(flags) ((flags) & QR_MASK)
#define IS_OPCODE(flags, op) (((flags) & OPCODE_MASK) >> 11 == (op))
#define IS_AA(flags) ((flags) & AA_MASK)
#define IS_TC(flags) ((flags) & TC_MASK)
#define IS_RD(flags) ((flags) & RD_MASK)
#define IS_RA(flags) ((flags) & RA_MASK)
#define IS_Z(flags) ((flags) & Z_MASK)
#define IS_RCODE(flags, code) (((flags) & RCODE_MASK) == (code))

#endif /* __DNS_HPP__ */
