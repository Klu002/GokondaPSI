#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "../../include-shared/util.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;

  this->local_set = std::unordered_set<std::string>();
}

std::vector<CryptoPP::Integer> exponentiateInts(
  std::vector<CryptoPP::Integer> ints,
  CryptoPP::Integer exponent,
  CryptoPP::Integer mod) {
  std::vector<CryptoPP::Integer> exponentiated_ints;
  for (auto &i: ints) {
    exponentiated_ints.push_back(
      CryptoPP::ModularExponentiation(i, exponent, mod)
    );
  }

  return exponentiated_ints;
}
/**
 * Requests the PSI of the client's current set and the target client's current set
 */
void Client::GetPSI() {
  // Setup: Generate private exponent k
  CryptoPP::AutoSeededRandomPool prg;
  CryptoPP::Integer k(prg, 0, DL_Q);

  // Round 1: Requester sends H(local_set_r)^k_r
  std::vector<CryptoPP::Integer> int_arr;
  for (auto const &str: this->local_set) {
    std::string hash_str = this->crypto_driver->hash(str);
    int_arr.push_back(CryptoPP::Integer(hash_str.c_str()));
  }

  std::vector<CryptoPP::Integer> exponentiated_hash_ints = exponentiateInts(int_arr, k, DL_P);
  std::random_shuffle(exponentiated_hash_ints.begin(), exponentiated_hash_ints.end());
  PSIRequest_Message req_msg;
  req_msg.hashed_exponentiated_eles = exponentiated_hash_ints;
  this->network_driver->send(
    this->crypto_driver->encrypt_and_tag(
      this->AES_key, this->HMAC_key, &req_msg
    )
  );

  // Round 2: Requester recieves H(local_set_r)^(k_r k_s) and H(local_set_s)^k_s
  PSIResponse_Message resp_msg;
  auto [serialized_resp, is_valid] = this->crypto_driver->decrypt_and_verify(
    this->AES_key, this->HMAC_key, this->network_driver->read()
  );
  if (!is_valid) {
    throw std::runtime_error("Recieved invalid response message for PSI");
  }
  resp_msg.deserialize(serialized_resp);

  // Round 3: Requester computes H(local_set_s)^(k_s k_r) and the intersection
  std::vector<CryptoPP::Integer> resp_shared_exponent = exponentiateInts(resp_msg.resp_hashed_exponentiated_eles, k, DL_P);
  std::vector<CryptoPP::Integer> intersection;
  for (auto &req: resp_msg.req_hashed_exponentiated_eles) {
      if (std::find(resp_shared_exponent.begin(), resp_shared_exponent.end(), req) != resp_shared_exponent.end()) {
        intersection.push_back(req);
      }
  }

  // Decrypt and return
  

}


/**
 * Responds with the PSI of the client's current set and the requester client's current set
 */
void Client::RespondPSI() {

  
}

void Client::HandlePut(std::string element) {
  this->local_set.insert(element);
}

void Client::HandleDelete(std::string element) {
  try{
    this->local_set.erase(element);
  }
  catch(...) {
    std::printf("Failed to insert element %s\n", element);
  }
}

void Client::HandleDump() {
  for (auto const &ele: this->local_set) {
    std::cout << ele << ", ";
  }
  std::cout << std::endl;
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();
  REPLDriver<Client> repl = REPLDriver<Client>(this);

  // Run key exchange.
  auto keys = this->HandleKeyExchange(command);
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;

  // Start REPL
  repl.add_action("getPSI", "getPSI", &Client::GetPSI);
  repl.add_action("respondPSI", "respondPSI", &Client::RespondPSI);
  repl.add_action("put", "put <element>", Client::HandlePut);
  repl.add_action("delete", "delete <element>", Client::HandleDelete);
  repl.add_action("dump", "dump", Client::HandleDump);
  repl.run();
}

/**
 * Run key exchange.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
Client::HandleKeyExchange(std::string command) {
  // TODO: implement me!
  auto dh_values = this->crypto_driver->DH_initialize();

  if (command == "listen") {
    // Listen for g^a
    std::vector<unsigned char> user_public_value = this->network_driver->read();
    DHPublicValue_Message user_public_value_s;
    user_public_value_s.deserialize(user_public_value);

    // Respond with m = (g^b, g^a) signed with our private DSA key
    DHPublicValue_Message public_value_s;
    public_value_s.public_value = std::get<2>(dh_values);
    std::vector<unsigned char> public_value_data;
    public_value_s.serialize(public_value_data);
    this->network_driver->send(public_value_data);
  }
  else if (command == "connect") {
    // Send m = (g^b, g^a) signed with our private DSA key
    DHPublicValue_Message public_value_s;
    public_value_s.public_value = std::get<2>(dh_values);
    std::vector<unsigned char> public_value_data;
    public_value_s.serialize(public_value_data);
    this->network_driver->send(public_value_data);

    // Listen for g^a
    std::vector<unsigned char> server_public_value = this->network_driver->read();
    DHPublicValue_Message server_public_value_s;
    server_public_value_s.deserialize(server_public_value);
  }
  else {
    throw std::runtime_error("Invalid command pased to Client::HandleKeyExchange");
  }

  // Recover g^ab
  auto dh_shared_key = this->crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.public_value);

  // Generate keys
  auto AES_key = this->crypto_driver->AES_generate_key(dh_shared_key);
  auto HMAC_key = this->crypto_driver->HMAC_generate_key(dh_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  return keys;
}