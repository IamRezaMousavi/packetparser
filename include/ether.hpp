#ifndef ETHER_HPP
#define ETHER_HPP

#include <netinet/ether.h>

#include <cstdint>
#include <span>

#include "layer.hpp"

class Ether : public Layer {
public:
  struct ether_addr shost;        /**< source mac address host. */
  struct ether_addr dhost;        /**< destination mac address host. */
  uint16_t          eth_type = 0; /**< packet ethernet type. */

  Ether()                         = default;
  Ether(const Ether &)            = default;
  Ether &operator=(const Ether &) = default;
  Ether(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* ETHER_HPP */
