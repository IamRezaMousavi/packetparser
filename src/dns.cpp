#include "dns.hpp"

#include <netinet/in.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>

inline bool isCompressionPointer(uint8_t label_byte) noexcept { return (label_byte & 0xC0) == 0xC0; }

inline bool isEndOfName(uint8_t label_byte) noexcept { return label_byte == 0x00; }

static uint16_t extractCompressionOffset(std::span<const uint8_t> msg, size_t position) {
  if (position + 1 >= msg.size())
    throw std::runtime_error("DNS compression pointer out of bounds");

  const uint16_t offset = (static_cast<uint16_t>(msg[position] & 0x3F) << 8) | msg[position + 1];

  if (offset >= msg.size())
    throw std::runtime_error("DNS compression pointer points outside message");

  return offset;
}

static std::string_view extractLabel(std::span<const uint8_t> msg, size_t position, uint8_t label_length) {
  if (label_length > 63)
    throw std::runtime_error("DNS label length > 63");

  if (position + label_length > msg.size())
    throw std::runtime_error("DNS label out of bounds");

  return std::string_view(reinterpret_cast<const char *>(&msg[position]), label_length);
}

static std::string parseDNSQueryName(std::span<const uint8_t> full_msg, size_t &offset) {
  std::ostringstream name;
  size_t             cursor     = offset;
  bool               has_jumped = false;

  while (cursor < full_msg.size()) {
    const uint8_t label_byte = full_msg[cursor];

    if (isEndOfName(label_byte)) {
      if (!has_jumped)
        offset = cursor + 1;
      break;
    }

    if (isCompressionPointer(label_byte)) {
      const uint16_t target_offset = extractCompressionOffset(full_msg, cursor);

      if (target_offset >= cursor)
        throw std::runtime_error("DNS compression pointer does not point backwards");

      if (!has_jumped) {
        offset     = cursor + 2; // pointer is 2 bytes
        has_jumped = true;
      }

      cursor = target_offset;
      continue;
    }

    // normal label
    cursor++;
    const auto label = extractLabel(full_msg, cursor, label_byte);

    if (!name.str().empty())
      name << '.';

    name << label;
    cursor += label_byte;

    if (!has_jumped)
      offset = cursor;
  }

  return name.str();
}

DNSQuery::DNSQuery(std::span<const uint8_t> full_msg, size_t offset) {
  if (offset >= full_msg.size())
    throw std::runtime_error("DNSQuery: offset out of bounds");

  const size_t start = offset;
  name               = parseDNSQueryName(full_msg, offset);

  if (offset + 4 > full_msg.size())
    throw std::runtime_error("DNSQuery: not enough data for type/class");

  qtype = static_cast<QType>(ntohs(*reinterpret_cast<const uint16_t *>(full_msg.data() + offset)));
  offset += 2;

  qclass = static_cast<QClass>(ntohs(*reinterpret_cast<const uint16_t *>(full_msg.data() + offset)));
  offset += 2;

  m_size = offset - start;
}

size_t DNSQuery::size() const { return m_size; }

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

DNS::DNS(std::span<const uint8_t> data) {
  if (data.size() < sizeof(DNSHeader))
    throw std::runtime_error("DNS: packet too short");

  const DNSHeader *dnsHeader = (DNSHeader *)data.data();
  h.transactionId            = ntohs(dnsHeader->transactionId);
  h.flags                    = ntohs(dnsHeader->flags);
  h.queriesCount             = ntohs(dnsHeader->queriesCount);
  h.answersCount             = ntohs(dnsHeader->answersCount);
  h.authoritiesCount         = ntohs(dnsHeader->authoritiesCount);
  h.additionalsCount         = ntohs(dnsHeader->additionalsCount);

  size_t offset = sizeof(DNSHeader);
  for (int i = 0; i < h.queriesCount; ++i) {
    if (offset >= data.size())
      throw std::runtime_error("DNS: truncated query section");

    queries.push_back(DNSQuery(data, offset));
    offset += queries.back().size();
  }

  m_size = offset;
}

size_t DNS::size() const { return m_size; }

std::unique_ptr<Layer> DNS::clone() const { return std::make_unique<DNS>(*this); }

std::string DNS::toString() const {
  std::ostringstream ss;
  ss << "|                 DNS                  |\n";
  ss << "+------------------+-------------------+\n";
  ss << "|   Transaction ID | 0x" << std::left << std::setw(15) << std::hex << h.transactionId << std::dec << " |\n";
  ss << "|            Flags | 0x" << std::left << std::setw(15) << std::hex << h.flags << std::dec << " |\n";
  ss << "|        Questions | " << std::left << std::setw(17) << h.queriesCount << " |\n";
  ss << "|       Answer PRs | " << std::left << std::setw(17) << h.answersCount << " |\n";
  ss << "|    Authority PRs | " << std::left << std::setw(17) << h.authoritiesCount << " |\n";
  ss << "|   Additional PRs | " << std::left << std::setw(17) << h.additionalsCount << " |\n";
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
