#ifndef __DNS_HPP__
#define __DNS_HPP__

#include "layer.hpp"

enum class QType : uint16_t {
  A = 0x01,
  NS = 0x02,
  CNAME = 0x05,
  SOA = 0x06,
  PTR = 0x0C,
  MX = 0x0F,
  TXT = 0x10,
  AAAA = 0x1C,
  SRV = 0x21,
  ANY = 0xFF
};

enum class QClass : uint16_t { IN = 0x01, CS = 0x02, CH = 0x03, HS = 0x04, ANY = 0xFF };

class DNSQuery {
public:
  std::string name;
  QType qtype;
  QClass qclass;

  DNSQuery(const uint8_t *data, int &offset);
  std::string toString() const;

private:
  /**
   * parse dns query name from binary data.
   * @param data pointer to binary data.
   * @param offset start offset from data pointer.
   */
  std::string parseDNSQueryName(const u_char *data, int &offset);

  std::string toString(QType type) const;
  std::string toString(QClass qclass) const;
};

class DNS : public Layer {
public:
  uint16_t transactionId;
  uint16_t flags;

  uint16_t queriesCount;
  uint16_t answersCount;
  uint16_t authoritiesCount;
  uint16_t additionalsCount;

  std::vector<DNSQuery> queries;

  DNS() = default;
  DNS(const DNS &) = default;
  DNS &operator=(const DNS &) = default;
  DNS(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const;
  std::unique_ptr<Layer> clone() const override;
};

std::ostream &operator<<(std::ostream &os, const DNS &dns);

#endif /* __DNS_HPP__ */
