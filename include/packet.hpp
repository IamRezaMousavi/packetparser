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

class Packet {
public:
  std::vector<std::unique_ptr<Layer>> layers;

  Packet() = default;
  Packet(Packet &&) = default;
  Packet &operator=(Packet &&) = default;
  Packet(const Packet &other);
  Packet &operator=(const Packet &other);

  void addLayer(const Layer &l);
  std::string toString() const;

  template <typename T> T *get() const {
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

inline Packet operator/(Ether &ether, IP &ip) {
  Packet pkt;
  pkt.addLayer(ether);
  pkt.addLayer(ip);
  return pkt;
}

#endif /* __PACKET_HPP__ */
