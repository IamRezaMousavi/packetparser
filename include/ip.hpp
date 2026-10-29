#ifndef IP_HPP
#define IP_HPP

#include <netinet/ip.h>

#include <span>

#include "layer.hpp"

class IP : public Layer {
public:
  struct in_addr src;      /**< source ip address. */
  struct in_addr dst;      /**< destination ip address. */
  uint8_t        protocol; /**< ip protocol type. */
  uint8_t        ihl;      /**< ip header length. */

  IP()                      = default;
  IP(const IP &)            = default;
  IP &operator=(const IP &) = default;
  IP(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* IP_HPP */
