#ifndef __DNS_HPP__
#define __DNS_HPP__

#include <cinttypes>
#include <iomanip>
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
  uint16_t transactionId;
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
  uint16_t transactionId;
  uint16_t flags;

  uint16_t queriesCount;
  uint16_t answersCount;
  uint16_t authoritiesCount;
  uint16_t additionalsCount;

  std::vector<DNSQuery> queries;
};

std::string parseDNSQueryName(const u_char *data, int &offset);

DNSQuery parseDNSQuery(const u_char *data, int &offset);

DNS parseDNS(const u_char *data);

std::string QTypeToString(QType type);

std::string QClassToString(QClass qclass);

std::ostream &operator<<(std::ostream &os, const DNSQuery &query);

std::ostream &operator<<(std::ostream &os, const DNS &packet);

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
