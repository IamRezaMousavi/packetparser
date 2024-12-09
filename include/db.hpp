#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

#include <cstdbool>
#include <set>

class DB {

public:
  DB();
  ~DB();

  bool insert_servername(std::string appname, std::set<std::string> servernames);

private:
  sql::Driver *driver;
  sql::Connection *con;
};

#endif /* __DB__HPP__ */
