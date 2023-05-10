#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/pkg/agent.hpp"

/*
 * Usage: ./pir_agent
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (argc != 5) {
    std::cout << "Usage: ./pir_agent <address> <port> <dimension> <sidelength>"
              << std::endl;
    return 1;
  }
  std::string address = argv[1];
  int port = std::stoi(argv[2]);
  int d = std::stoi(argv[3]);
  int s = std::stoi(argv[4]);

  // Create client object and run
  AgentClient agent = AgentClient(address, port, d, s);
  agent.run();
  return 0;
}
