#ifndef __LAYER_HPP__
#define __LAYER_HPP__

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class Layer {
public:
  virtual std::vector<uint8_t> serialize() const = 0;
  virtual std::string toString() const = 0;
  virtual std::unique_ptr<Layer> clone() const = 0;
  virtual ~Layer() = default;

  const uint8_t *payload() const { return payloadPtr; }
  size_t payloadSize() const { return payloadLen; }

protected:
  const uint8_t *payloadPtr = nullptr;
  size_t payloadLen = 0;
};

#endif /* __LAYER_HPP__ */
