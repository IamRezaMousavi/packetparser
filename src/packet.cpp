#include "packet.hpp"

#include <sstream>

Packet::Packet(const Packet &other) {
  for (const auto &l : other.layers)
    layers.push_back(l->clone());
}

Packet &Packet::operator=(const Packet &other) {
  if (this != &other) {
    layers.clear();
    for (const auto &l : other.layers)
      layers.push_back(l->clone());
  }
  return *this;
}

void Packet::addLayer(const Layer &l) { layers.push_back(l.clone()); }

std::string Packet::toString() const {
  std::ostringstream ss;
  for (const auto &l : layers)
    ss << l->toString() << '\n';
  return ss.str();
}

Packet Packet::operator/(UDP &udp) {
  addLayer(udp);
  return *this;
}

Packet Packet::operator/(DNS &dns) {
  addLayer(dns);
  return *this;
}

Packet Packet::operator/(TCP &tcp) {
  addLayer(tcp);
  return *this;
}

Packet Packet::operator/(TLS &tls) {
  addLayer(tls);
  return *this;
}
