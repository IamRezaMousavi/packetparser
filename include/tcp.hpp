#ifndef __TCP_HPP__
#define __TCP_HPP__

#include "layer.hpp"

class TCP : public Layer {
public:
  uint16_t sport;
  uint16_t dport;

  TCP() = default;
  TCP(const TCP &) = default;
  TCP &operator=(const TCP &) = default;
  TCP(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* __TCP_HPP__ */
