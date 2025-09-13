#ifndef __UDP_HPP__
#define __UDP_HPP__

#include "layer.hpp"

class UDP : public Layer {
public:
  uint16_t sport;
  uint16_t dport;

  UDP() = default;
  UDP(const UDP &) = default;
  UDP &operator=(const UDP &) = default;
  UDP(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* __UDP_HPP__ */
