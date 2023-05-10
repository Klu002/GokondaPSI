#pragma once

#include <mutex>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>

class HypercubeDriver {
public:
  HypercubeDriver(int d, int s, CryptoPP::Integer q);
  void insert(int idx, CryptoPP::Integer x);
  CryptoPP::Integer get(int idx);
  std::vector<int> to_coords(int idx);
  int from_coords(std::vector<int> coords);

private:
  std::mutex mtx;
  int d, s;
  CryptoPP::Integer q;
  std::vector<CryptoPP::Integer> data;
};