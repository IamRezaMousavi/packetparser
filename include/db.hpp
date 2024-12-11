#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

#include <cstdbool>
#include <set>
#include <string>
#include <vector>

#include "dns.hpp"
#include "tls.hpp"

class DB {

public:
  DB();
  ~DB();

  bool insert_dnses(std::vector<DNSPacket> dnsPackets);
  bool insert_tlses(std::vector<TLSPacket> tlsPackets);

  bool insert_dns(DNSPacket dnsPacket);
  bool insert_tls(TLSPacket tlsPacket);

  void setAppname(std::string appname);

private:
  sql::Driver *driver;
  sql::Connection *con;

  std::string appname;
};

#endif /* __DB__HPP__ */
