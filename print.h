#pragma once

#include <iostream>

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

