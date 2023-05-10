#pragma once

#include "seal/seal.h"

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class CloudClient {
public:
  CloudClient(int d, int s);
  void run(int port);
  void HandleInsert(std::string input);
  void HandleGet(std::string input);

  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);
  void HandleSend(std::shared_ptr<NetworkDriver> network_driver,
                  std::shared_ptr<CryptoDriver> crypto_driver);

private:
  int dimension, sidelength;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<HypercubeDriver> hypercube_driver;

  void ListenForConnections(int port);
};
