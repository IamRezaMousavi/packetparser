#include "db.hpp"

#include <arpa/inet.h>

#include <iostream>

#include "dns.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "tls.hpp"
#include "udp.hpp"

DBConnection::DBConnection(const DBConfig &dbconfig) : config(dbconfig) {
  connect();
  init_table();
}

bool DBConnection::is_connected() const {
  if (!connection_)
    return false;
  return mysql_ping(connection_.get()) == 0;
}

void DBConnection::connect() {
  MYSQL *raw = mysql_init(nullptr);
  if (!raw)
    throw std::runtime_error("mysql_init failed");

  connection_.reset(raw);

  if (!mysql_real_connect(
          connection_.get(), config.host.c_str(), config.username.c_str(), config.password.c_str(),
          config.dbname.c_str(), config.port, nullptr, 0
      )) {
    std::string err = mysql_error(connection_.get());
    connection_.reset(); // closes the connection
    throw std::runtime_error(std::string("mysql_connect failed: ") + err);
  }
}

void DBConnection::close() { connection_.reset(); }

void DBConnection::reconnect() {
  close();
  connect();
}

void DBConnection::init_table() {
  const std::string create_table =
      "CREATE TABLE IF NOT EXISTS testreg( "
      "id INT PRIMARY KEY AUTO_INCREMENT, "
      "timestamp TIMESTAMP NOT NULL DEFAULT NOW(), "
      "appname VARCHAR(10), "
      "packettype ENUM('DNS', 'TLS'), "
      "servername TEXT, "
      "ip VARCHAR(15), "
      "port SMALLINT UNSIGNED)";

  if (mysql_query(connection_.get(), create_table.c_str()) != 0)
    throw std::runtime_error(mysql_error(connection_.get()));
}

DBConnection::MysqlStmtPtr DBConnection::prepare_statement() {
  MYSQL_STMT *raw = mysql_stmt_init(connection_.get());
  if (!raw)
    throw std::runtime_error("mysql_stmt_init failed");

  MysqlStmtPtr      stmt(raw);
  const std::string query =
      "INSERT INTO testreg "
      "(appname, packettype, servername, ip, port) "
      "VALUES "
      "(?, ?, ?, ?, ?)";

  if (mysql_stmt_prepare(stmt.get(), query.c_str(), query.size()) != 0)
    throw std::runtime_error(mysql_stmt_error(stmt.get()));
  return stmt;
}

bool DBConnection::insert_dnses(const std::vector<Packet> &dnsPackets) {
  for (auto &dnsPacket : dnsPackets) {
    insert_dns(dnsPacket);
  }
  return true;
}

bool DBConnection::insert_tlses(const std::vector<Packet> &tlsPackets) {
  for (auto &tlsPacket : tlsPackets) {
    insert_tls(tlsPacket);
  }
  return true;
}

static std::string in_addr_to_string(const in_addr &addr) {
  char buffer[INET_ADDRSTRLEN];

  if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
    throw std::runtime_error("Failed to convert in_addr to string");
  }
  return std::string(buffer);
}

bool DBConnection::insert_dns(const Packet &dnsPacket) {
  try {
    if (!is_connected()) {
      reconnect();
    }

    auto stmt = prepare_statement();

    const std::vector<std::string> values{
        this->appname, std::string("DNS"), dnsPacket.get<DNS>()->queries.at(0).name,
        in_addr_to_string(dnsPacket.get<IP>()->dst), std::to_string(dnsPacket.get<UDP>()->dport)
    };

    std::vector<MYSQL_BIND>    binds(values.size());
    std::vector<unsigned long> lengths(values.size());

    for (size_t i = 0; i < values.size(); ++i) {
      binds[i].buffer_type   = MYSQL_TYPE_STRING;
      binds[i].buffer        = const_cast<char *>(values[i].data());
      lengths[i]             = static_cast<unsigned long>(values[i].size());
      binds[i].buffer_length = lengths[i];
      binds[i].length        = &lengths[i];
    }

    if (mysql_stmt_bind_param(stmt.get(), binds.data()) != 0)
      throw std::runtime_error(mysql_stmt_error(stmt.get()));

    if (mysql_stmt_execute(stmt.get()) != 0)
      throw std::runtime_error(mysql_stmt_error(stmt.get()));

  } catch (std::exception &e) {
    std::cerr << "db insert error: " << e.what() << "\n";
    return false;
  }
  std::cout << "db insert dns successfully\n";
  return true;
}

bool DBConnection::insert_tls(const Packet &tlsPacket) {
  try {
    if (!is_connected()) {
      reconnect();
    }

    auto stmt = prepare_statement();

    const std::vector<std::string> values{
        this->appname, std::string("TLS"),
        tlsPacket.get<TLS>()->handshake.value().extensions.at(0).servername.value().name,
        in_addr_to_string(tlsPacket.get<IP>()->dst), std::to_string(tlsPacket.get<TCP>()->dport)
    };

    std::vector<MYSQL_BIND>    binds(values.size());
    std::vector<unsigned long> lengths(values.size());

    for (size_t i = 0; i < values.size(); ++i) {
      binds[i].buffer_type   = MYSQL_TYPE_STRING;
      binds[i].buffer        = const_cast<char *>(values[i].data());
      lengths[i]             = static_cast<unsigned long>(values[i].size());
      binds[i].buffer_length = lengths[i];
      binds[i].length        = &lengths[i];
    }

    if (mysql_stmt_bind_param(stmt.get(), binds.data()) != 0)
      throw std::runtime_error(mysql_stmt_error(stmt.get()));

    if (mysql_stmt_execute(stmt.get()) != 0)
      throw std::runtime_error(mysql_stmt_error(stmt.get()));

  } catch (std::exception &e) {
    std::cerr << "db insert error: " << e.what() << "\n";
    return false;
  }
  std::cout << "db insert tls successfully\n";
  return true;
}

void DBConnection::setAppname(const std::string &appname) { this->appname = appname; }
