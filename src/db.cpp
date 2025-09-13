#include "db.hpp"

#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

#include <iostream>

#include "dns.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "tls.hpp"
#include "udp.hpp"

DB::DB() {
  try {
    driver = get_driver_instance();
    con = driver->connect("tcp://192.168.108.133:3306", "root", "1qaz!QAZ");
    con->setSchema("reza_log");

    sql::Statement *stmt = con->createStatement();
    stmt->execute("CREATE TABLE IF NOT EXISTS testreg("
                  "id INT PRIMARY KEY AUTO_INCREMENT,"
                  "timestamp TIMESTAMP NOT NULL DEFAULT NOW(),"
                  "appname VARCHAR(10),"
                  "packettype ENUM('DNS', 'TLS'),"
                  "servername TEXT,"
                  "ip VARCHAR(15),"
                  "port SMALLINT UNSIGNED)");
    stmt->execute("CREATE TABLE IF NOT EXISTS test(id INT, label CHAR(1))");
    stmt->execute("INSERT INTO test(id, label) VALUES (1, 'a')");
    sql::PreparedStatement *prep_stmt = con->prepareStatement("INSERT INTO test(id, label) VALUES (?, ?)");
    prep_stmt->setInt(1, 1);
    prep_stmt->setString(2, "a");
    prep_stmt->execute();

    prep_stmt->setInt(1, 2);
    prep_stmt->setString(2, "b");
    prep_stmt->execute();

    sql::ResultSet *res = stmt->executeQuery("SELECT 'Hello World!' AS _message");
    while (res->next()) {
      std::cout << "\t... MySQL replies: ";
      std::cout << res->getString("_message") << std::endl;
      std::cout << "\t... MySQL says it again: ";
      std::cout << res->getString(1) << std::endl;
    }

    delete res;
    delete prep_stmt;
    delete stmt;

  } catch (sql::SQLException &e) {

    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
  }
}

bool DB::insert_dnses(std::vector<Packet> dnsPackets) {
  for (auto &dnsPacket : dnsPackets) {
    insert_dns(dnsPacket);
  }
  return true;
}

bool DB::insert_tlses(std::vector<Packet> tlsPackets) {
  for (auto &tlsPacket : tlsPackets) {
    insert_tls(tlsPacket);
  }
  return true;
}

bool DB::insert_dns(Packet &dnsPacket) {
  sql::PreparedStatement *pstmt = con->prepareStatement(
      "INSERT INTO testreg (appname, packettype, servername, ip, port) VALUES (?, 'DNS', ?, ?, ?)");
  try {
    pstmt->setString(1, this->appname);
    if (auto dns = dnsPacket.get<DNS>()) {
      pstmt->setString(2, dns->queries.at(0).name);
    }
    if (auto ip = dnsPacket.get<IP>()) {
      pstmt->setString(3, ip->dst);
    }
    if (auto udp = dnsPacket.get<UDP>()) {
      pstmt->setInt(4, udp->dport);
    }
    pstmt->executeUpdate();

  } catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return false;
  }
  delete pstmt;
  return true;
}

bool DB::insert_tls(Packet &tlsPacket) {
  sql::PreparedStatement *pstmt = con->prepareStatement(
      "INSERT INTO testreg (appname, packettype, servername, ip, port) VALUES (?, 'TLS', ?, ?, ?)");
  try {
    pstmt->setString(1, this->appname);
    if (auto tls = tlsPacket.get<TLS>()) {
      pstmt->setString(2, tls->handshake.value().extensions.at(0).servername.name);
    }
    if (auto ip = tlsPacket.get<IP>()) {
      pstmt->setString(3, ip->dst);
    }
    if (auto udp = tlsPacket.get<TCP>()) {
      pstmt->setInt(4, udp->dport);
    }
    pstmt->executeUpdate();

  } catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return false;
  }
  delete pstmt;
  return true;
}

void DB::setAppname(std::string appname) { this->appname = appname; }

DB::~DB() {
  sql::Statement *stmt = con->createStatement();
  stmt->execute("DELETE FROM test");
  stmt->execute("INSERT INTO test(id, label) VALUES (1, 'a')");
  delete stmt;
  delete con;
}
