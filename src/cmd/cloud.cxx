#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include/pkg/cloud.hpp"

/*
 * Usage: ./pir_cloud
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 4)) {
    std::cout << "Usage: ./pir_cloud <port> <dimension> <sidelength>"
              << std::endl;
    return 1;
  }
  int port = std::stoi(argv[1]);
  int d = std::stoi(argv[2]);
  int s = std::stoi(argv[3]);

  // Create a cloud object and run.
  CloudClient cloud = CloudClient(d, s);
  cloud.run(port);
  return 0;
}
