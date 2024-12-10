#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

#include <cstdbool>
#include <set>
#include <vector>

#include "dns.hpp"
#include "tls.hpp"

class DB {

public:
  DB();
  ~DB();

  bool insert_dns(std::string appname, std::vector<DNSPacket> dnsPackets);
  bool insert_tls(std::string appname, std::vector<TLSPacket> tlsPackets);

private:
  sql::Driver *driver;
  sql::Connection *con;
};

#endif /* __DB__HPP__ */
