#ifndef DNS_HPP
#define DNS_HPP

#include <span>
#include <vector>

#include "layer.hpp"

enum class QType : uint16_t {
  A     = 0x01,
  NS    = 0x02,
  CNAME = 0x05,
  SOA   = 0x06,
  PTR   = 0x0C,
  MX    = 0x0F,
  TXT   = 0x10,
  AAAA  = 0x1C,
  SRV   = 0x21,
  ANY   = 0xFF
};

enum class QClass : uint16_t {
  IN  = 0x01,
  CS  = 0x02,
  CH  = 0x03,
  HS  = 0x04,
  ANY = 0xFF
};

class DNSQuery {
public:
  std::string name;
  QType       qtype;
  QClass      qclass;

  DNSQuery(std::span<const uint8_t> data, size_t offset);
  std::string toString() const;

  size_t size() const;

private:
  size_t m_size = 0;

  std::string toString(QType type) const;
  std::string toString(QClass qclass) const;
};

struct DNSHeader {
  uint16_t transactionId;
  uint16_t flags;
  uint16_t queriesCount;
  uint16_t answersCount;
  uint16_t authoritiesCount;
  uint16_t additionalsCount;
};

class DNS : public Layer {
public:
  DNSHeader             h;
  std::vector<DNSQuery> queries;

  DNS()                       = default;
  DNS(const DNS &)            = default;
  DNS &operator=(const DNS &) = default;
  DNS(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;

private:
  size_t m_size = 0;
};

std::ostream &operator<<(std::ostream &os, const DNS &dns);

#endif /* DNS_HPP */
