#ifndef __LAYER_HPP__
#define __LAYER_HPP__

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/**
 * An interface class to each network packet layers.
 */
class Layer {
public:
  /**
   * Serialize layer data to send on network.
   * @return List of serialized data.
   */
  virtual std::vector<uint8_t> serialize() const = 0;
  /**
   * Convert layer data to beauty style string.
   * @return beauty style string.
   */
  virtual std::string toString() const = 0;
  /**
   * A method to implement clone feature to layer objects.
   * @return unique pointer to new created object.
   */
  virtual std::unique_ptr<Layer> clone() const = 0;

  virtual ~Layer() = default;

  /**
   * Return a pointer to layer payload.
   * @return pointer to layer payload data.
   */
  const uint8_t *payload() const { return payloadPtr; }
  /**
   * Return layer payload length.
   * @return length of payload data.
   */
  size_t payloadSize() const { return payloadLen; }

protected:
  const uint8_t *payloadPtr = nullptr;
  size_t         payloadLen = 0;
};

#endif /* __LAYER_HPP__ */
