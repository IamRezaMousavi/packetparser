#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

#include <string>
#include <vector>

#include "packet.hpp"

/**
 * Database wrapper class.
 */
class DB {
public:
  DB();
  ~DB();

  /**
   * insert many dns packets data to database.
   * @param dnsPackets dns packets.
   * @return success or failed.
   */
  bool insert_dnses(std::vector<Packet> dnsPackets);
  /**
   * insert many tls packets data to database.
   * @param tlsPackets tls packets.
   * @return success or failed.
   */
  bool insert_tlses(std::vector<Packet> tlsPackets);

  /**
   * insert a dns packet data to database.
   * @param dnsPacket a dns packet object.
   * @return success or failed.
   */
  bool insert_dns(Packet &dnsPacket);
  /**
   * insert a tls packet data to database.
   * @param dnsPacket a tls packet object.
   * @return success or failed.
   */
  bool insert_tls(Packet &tlsPacket);

  /**
   * set app name that packet belong to.
   * @param appname name of the app.
   */
  void setAppname(std::string appname);

private:
  sql::Driver     *driver;
  sql::Connection *con;

  std::string appname;
};

#endif /* __DB__HPP__ */
