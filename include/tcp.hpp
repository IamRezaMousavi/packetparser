#ifndef TCP_HPP
#define TCP_HPP

#include <span>

#include "layer.hpp"

class TCP : public Layer {
public:
  uint16_t sport; /**< source port. */
  uint16_t dport; /**< destination port. */
  uint8_t  thl;   /**< tcp header length. */

  TCP()                       = default;
  TCP(const TCP &)            = default;
  TCP &operator=(const TCP &) = default;
  TCP(std::span<const uint8_t> data);

  size_t                 size() const override;
  std::string            toString() const override;
  std::unique_ptr<Layer> clone() const override;
};

#endif /* TCP_HPP */
