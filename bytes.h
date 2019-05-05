#pragma once

#include <iostream>

typedef std::vector<uint8_t> Bytes;
typedef std::unique_ptr<Bytes> PBytes;

inline std::ostream &operator<<(std::ostream &out, Bytes const &b) {
  out << std::hex;
  for (auto abyte : b)
  	out << b;
  return out;
  //return std::cout << b.str();
}


void print() {
}

template <typename T> void print(const T& t) {
    std::cout << t << std::endl;
}

template <typename First, typename... Rest> void print(const First& first, const Rest&... rest) {
    std::cout << first;
    print(rest...); // recursive call using pack expansion syntax
}

void println() {
    std::cout << std::endl;
}

template <typename T> void println(const T& t) {
    std::cout << t << std::endl;
}

template <typename First, typename... Rest> void println(const First& first, const Rest&... rest) {
    std::cout << first;
    println(rest...); // recursive call using pack expansion syntax
}

