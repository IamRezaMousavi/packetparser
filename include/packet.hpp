#ifndef __PACKET_HPP__
#define __PACKET_HPP__

#include <memory>
#include <string>
#include <vector>

#include "dns.hpp"
#include "ether.hpp"
#include "ip.hpp"
#include "layer.hpp"
#include "tcp.hpp"
#include "tls.hpp"
#include "udp.hpp"

/**
 * Packet class used to hold all layers data of a packet.
 */
class Packet {
public:
  std::vector<std::unique_ptr<Layer>> layers;

  Packet()                     = default;
  Packet(Packet &&)            = default;
  Packet &operator=(Packet &&) = default;
  Packet(const Packet &other);
  Packet &operator=(const Packet &other);

  /**
   * Add a layer to packet.
   * @param l layer to add to packet.
   */
  void        addLayer(const Layer &l);
  std::string toString() const;

  /**
   * get a layer from packet.
   * @return layer object that stored in packet.
   */
  template <typename T>
  T *get() const {
    for (const auto &l : layers) {
      if (auto ptr = dynamic_cast<T *>(l.get()))
        return ptr;
    }
    return nullptr;
  }

  Packet operator/(UDP &udp);
  Packet operator/(DNS &dns);
  Packet operator/(TCP &tcp);
  Packet operator/(TLS &tls);
};

/**
 * Helper function to create a packet from L2 and L3.
 * @return created packet.
 */
inline Packet operator/(Ether &ether, IP &ip) {
  Packet pkt;
  pkt.addLayer(ether);
  pkt.addLayer(ip);
  return pkt;
}

#endif /* __PACKET_HPP__ */
