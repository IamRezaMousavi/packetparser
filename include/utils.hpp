#ifndef __UTILS_HPP__
#define __UTILS_HPP__

#include <cstdlib>
#include <iostream>
#include <string>

#define UNUSED(x) (void)(x)

inline void panic(std::string msg) {
  std::cerr << msg << std::endl;
  exit(EXIT_FAILURE);
}

#endif /* __UTILS_HPP__ */
