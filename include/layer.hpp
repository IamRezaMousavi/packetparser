#ifndef LAYER_HPP
#define LAYER_HPP

#include <cstdint>
#include <memory>
#include <string>

/**
 * An base class to each network packet layers.
 */
class Layer {
public:
  virtual std::string            toString() const = 0;
  virtual size_t                 size() const     = 0;
  virtual std::unique_ptr<Layer> clone() const    = 0;

  virtual ~Layer() = default;
};

#endif /* __LAYER_HPP__ */
