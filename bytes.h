#pragma once

#include <iostream>

typedef std::vector<uint8_t> Bytes;
typedef std::unique_ptr<Bytes> PBytes;

//
char encode_hexchar(uint8_t val) {
  if (val >= 10)
    return 'a' + (val - 10);
  return '0' + val;
}

uint8_t decode_hexchar(char val) {
  if (val >= 'a')
    return uint8_t(val - 'a' + 10);
  return uint8_t(val - '0');
}

inline std::ostream &operator<<(std::ostream &out, Bytes const &b) {
  // out << std::hex << std::setfill('0') << std::setw(2);
  for (auto abyte : b) {
    // std::cout << "byte: " << int(abyte) << " " << encode_hexchar(abyte >> 4) << " " << encode_hexchar(abyte & 15) << std::endl;
    out << encode_hexchar(abyte >> 4) << encode_hexchar(abyte & 15);
  	// out << int(abyte);
  }
  return out;// << std::dec;
  //return std::cout << b.str();
}

inline std::istream &operator>>(std::istream &in, Bytes &b) {
  while (true) {
    char byte1(0), byte2(0);
    in >> byte1 >> byte2;
    if (!in)
      break;

    uint8_t val = (decode_hexchar(byte1) << 4) + decode_hexchar(byte2);
    b.push_back(val);
  }
  return in;
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

