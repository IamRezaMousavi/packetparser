#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

#include <string>
#include <vector>

#include "packet.hpp"

class DB {

public:
  DB();
  ~DB();

  bool insert_dnses(std::vector<Packet> dnsPackets);
  bool insert_tlses(std::vector<Packet> tlsPackets);

  bool insert_dns(Packet &dnsPacket);
  bool insert_tls(Packet &tlsPacket);

  void setAppname(std::string appname);

private:
  sql::Driver *driver;
  sql::Connection *con;

  std::string appname;
};

#endif /* __DB__HPP__ */
