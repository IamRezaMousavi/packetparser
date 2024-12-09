#ifndef __DB__HPP__
#define __DB__HPP__

#include <cppconn/driver.h>

class DB {

public:
  DB();
  ~DB();

private:
  sql::Driver *driver;
  sql::Connection *con;
};

#endif /* __DB__HPP__ */
