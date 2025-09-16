#ifndef __UDP_HPP__
#define __UDP_HPP__

#include "layer.hpp"

class UDP : public Layer {
public:
  uint16_t sport; /**< source port. */
  uint16_t dport; /**< destination port. */

  UDP() = default;
  UDP(const UDP &) = default;
  UDP &operator=(const UDP &) = default;
  /**
   * Constructor to create UDP layer object.
   * @param data pointer to layer data.
   * @param totalLength data layer length.
   */
  UDP(const uint8_t *data, size_t totalLength);

  std::vector<uint8_t> serialize() const override { return {}; }
  std::string toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* __UDP_HPP__ */
