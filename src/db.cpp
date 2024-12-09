#include "db.hpp"

#include <iostream>

#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

DB::DB() {
  try {
    driver = get_driver_instance();
    con = driver->connect("tcp://192.168.108.133:3306", "root", "1qaz!QAZ");
    con->setSchema("reza_log");

    sql::Statement *stmt = con->createStatement();
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

DB::~DB() {
  sql::Statement *stmt = con->createStatement();
  stmt->execute("DELETE FROM test");
  stmt->execute("INSERT INTO test(id, label) VALUES (1, 'a')");
  delete stmt;
  delete con;
}
