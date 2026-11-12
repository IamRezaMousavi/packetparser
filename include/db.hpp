#ifndef DB_HPP
#define DB_HPP

#include <mysql.h>

#include <memory>
#include <string>
#include <vector>

#include "packet.hpp"

struct DBConfig {
  std::string host     = "127.0.0.1";
  uint16_t    port     = 3306;
  std::string username = "reza";
  std::string password = "r";
  std::string dbname   = "reza";
};

/**
 * Database wrapper class.
 */
class DBConnection {
public:
  explicit DBConnection(const DBConfig &dbconfig);
  ~DBConnection() = default;

  // non-copyable
  DBConnection(const DBConnection &)            = delete;
  DBConnection &operator=(const DBConnection &) = delete;

  // movable
  DBConnection(DBConnection &&other) noexcept            = default;
  DBConnection &operator=(DBConnection &&other) noexcept = default;

  /**
   * insert many dns packets data to database.
   * @param dnsPackets dns packets.
   * @return success or failed.
   */
  bool insert_dnses(const std::vector<Packet> &dnsPackets);
  /**
   * insert many tls packets data to database.
   * @param tlsPackets tls packets.
   * @return success or failed.
   */
  bool insert_tlses(const std::vector<Packet> &tlsPackets);

  /**
   * insert a dns packet data to database.
   * @param dnsPacket a dns packet object.
   * @return success or failed.
   */
  bool insert_dns(const Packet &dnsPacket);
  /**
   * insert a tls packet data to database.
   * @param dnsPacket a tls packet object.
   * @return success or failed.
   */
  bool insert_tls(const Packet &tlsPacket);

  /**
   * set app name that packet belong to.
   * @param appname name of the app.
   */
  void setAppname(const std::string &appname);

private:
  // custom deleters
  struct MysqlDeleter {
    void operator()(MYSQL *conn) const noexcept {
      if (conn)
        mysql_close(conn);
    }
  };

  struct MysqlStmtDeleter {
    void operator()(MYSQL_STMT *stmt) const noexcept {
      if (stmt)
        mysql_stmt_close(stmt);
    }
  };

  using MysqlPtr     = std::unique_ptr<MYSQL, MysqlDeleter>;
  using MysqlStmtPtr = std::unique_ptr<MYSQL_STMT, MysqlStmtDeleter>;

  std::string appname;
  DBConfig    config;
  MysqlPtr    connection_;

  bool         is_connected() const;
  void         connect();
  void         close();
  void         init_table();
  void         reconnect();
  MysqlStmtPtr prepare_statement();
};

#endif /* DB_HPP */
