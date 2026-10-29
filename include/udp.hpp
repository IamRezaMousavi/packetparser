#ifndef UDP_HPP
#define UDP_HPP

#include <span>

#include "layer.hpp"

class UDP : public Layer {
public:
  uint16_t sport; /**< source port. */
  uint16_t dport; /**< destination port. */

  UDP()                       = default;
  UDP(const UDP &)            = default;
  UDP &operator=(const UDP &) = default;
  UDP(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* UDP_HPP */
