#include <cmath>

#include "../../include/drivers/hypercube_driver.hpp"

/**
 * Constructor. Makes a hypercube of dimension d with side length s
 * that stores integers mod q.
 */
HypercubeDriver::HypercubeDriver(int d, int s, CryptoPP::Integer q) {
  this->d = d;
  this->s = s;
  this->q = q;
  this->data =
      std::vector<CryptoPP::Integer>(std::pow(s, d), CryptoPP::Integer::One());
}

/**
 * Insert x mod q at the given idx
 */
void HypercubeDriver::insert(int idx, CryptoPP::Integer x) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  if (idx > std::pow(this->s, this->d))
    throw std::runtime_error("Hypercube out of bounds");

  this->data[idx] = x % this->q;
}

/**
 * Get the value at the given idx, mod q
 */
CryptoPP::Integer HypercubeDriver::get(int idx) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  if (idx > std::pow(this->s, this->d))
    throw std::runtime_error("Hypercube out of bounds");

  return this->data[idx];
}

/**
 * Convert index to coordinates
 */
std::vector<int> HypercubeDriver::to_coords(int idx) {
  if (idx > std::pow(this->s, this->d))
    throw std::runtime_error("Hypercube out of bounds");

  std::vector<int> res;
  res.resize(this->d);
  for (int e = this->d - 1; e >= 0; e--) {
    res[this->d - e - 1] = 0;
    int step = std::pow(this->s, e);
    while (idx >= step) {
      idx -= step;
      res[this->d - e - 1] += 1;
    }
  }
  return res;
}

/**
 * Convert coords to index
 */
int HypercubeDriver::from_coords(std::vector<int> coords) {
  for (int x : coords)
    if (x >= this->s)
      throw std::runtime_error("Hypercube out of bounds");

  int res;
  for (int e = this->d - 1; e >= 0; e--) {
    int step = std::pow(this->s, e);
    res += step * coords[this->d - e - 1];
  }
  return res;
}
