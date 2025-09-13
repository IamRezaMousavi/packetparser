#ifndef __ETHER_HPP__
#define __ETHER_HPP__

#include "layer.hpp"

class Ether : public Layer {
public:
  std::string shost;
  std::string dhost;
  uint16_t eth_type;

  Ether() = default;
  Ether(const Ether &) = default;
  Ether &operator=(const Ether &) = default;
  Ether(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* __ETHER_HPP__ */
