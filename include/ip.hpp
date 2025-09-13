#ifndef __IP_HPP__
#define __IP_HPP__

#include "layer.hpp"

class IP : public Layer {
public:
  std::string src;
  std::string dst;
  uint8_t protocol;
  uint8_t ihl;

  IP() = default;
  IP(const IP &) = default;
  IP &operator=(const IP &) = default;
  IP(const uint8_t *data, size_t totalLength);

  size_t headerLength() const { return ihl; }
  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* __IP_HPP__ */
