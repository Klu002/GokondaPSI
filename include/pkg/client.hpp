#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include <unordered_set>

class Client {
public:
  Client(std::shared_ptr<NetworkDriver> network_driver,
         std::shared_ptr<CryptoDriver> crypto_driver);
  void prepare_keys(CryptoPP::DH DH_obj,
                    CryptoPP::SecByteBlock DH_private_value,
                    CryptoPP::SecByteBlock DH_other_public_value);
  void GetPSI();
  void RespondPSI();
  void run(std::string command);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::string command);
  void HandlePut(std::string element);
  void HandleDelete(std::string element);
  void HandleDump();

private:
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  SecByteBlock AES_key;
  SecByteBlock HMAC_key;

  std::unordered_set<std::string> local_set;
};
