#include <cmath>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/cloud.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
CloudClient::CloudClient(int d, int s) {
  this->dimension = d;
  this->sidelength = s;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();
  this->hypercube_driver = std::make_shared<HypercubeDriver>(
      d, s, CryptoPP::Integer(PLAINTEXT_MODULUS));
  initLogger();
}

/**
 * run
 */
void CloudClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&CloudClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Run REPL.
  REPLDriver<CloudClient> repl = REPLDriver<CloudClient>(this);
  repl.add_action("insert", "insert <key>", &CloudClient::HandleInsert);
  repl.add_action("get", "get <key>", &CloudClient::HandleGet);
  repl.run();
}

/**
 * Insert a value into the database
 */
void CloudClient::HandleInsert(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  this->local_set.insert(input_split[1]);
  this->cli_driver->print_success("Inserted value!");
}

/**
 * Get a value from the database
 */
void CloudClient::HandleGet(std::string input) {
  for (auto &e: this->local_set) {
    std::cout << e << " ";
  }
  std::cout << "\n";
}

/**
 * Listen for new connections
 */
void CloudClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&CloudClient::HandleSend, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Come to a shared secret
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
CloudClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Listen for g^a
  std::vector<unsigned char> user_public_value = network_driver->read();
  DHPublicValue_Message user_public_value_s;
  user_public_value_s.deserialize(user_public_value);

  // Respond with m = (g^b, g^a) signed with our private DSA key
  DHPublicValue_Message public_value_s;
  public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> public_value_data;
  public_value_s.serialize(public_value_data);
  network_driver->send(public_value_data);

  // Recover g^ab
  auto dh_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      user_public_value_s.public_value);

  // Generate keys
  auto AES_key = crypto_driver->AES_generate_key(dh_shared_key);
  auto HMAC_key = crypto_driver->HMAC_generate_key(dh_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  return keys;
}

/**
 * Obliviously send a value to the retriever. This function should:
 * 1) Generate parameters and context.
 * 2) Receive the selection vector.
 * 3) Evaluate and return a response using homomorphic operations.
 */
void CloudClient::HandleSend(std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver) {
  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(network_driver, crypto_driver);

  // TODO: implement me!
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Setup: Generate private exponent k
  CryptoPP::AutoSeededRandomPool prg;
  CryptoPP::Integer k(prg, 0, DL_Q);

  // Round 1 Responder receives H(local_set_r)^k_r
  PSIRequest_Message req_msg;
  auto[serialized_req, is_valid] = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!is_valid) {
    throw std::runtime_error("Recieved invalid response message for PSI");
  }
  req_msg.deserialize(serialized_req);

  // Round 2 Responder calculates H(local_set_s)^k_s and H(local_set_r)^(k_s k_r)
  std::vector<CryptoPP::Integer> int_arr;
  for (auto const &str: this->local_set) {
    std::string hash_str = crypto_driver->hash(str);
    int_arr.push_back(CryptoPP::Integer(hash_str.c_str()));
  }

  std::vector<CryptoPP::Integer> exponentiated_hash_ints = exponentiateInts(int_arr, k, DL_P);
  std::random_shuffle(exponentiated_hash_ints.begin(), exponentiated_hash_ints.end());
  PSIResponse_Message resp_msg;
  resp_msg.resp_hashed_exponentiated_eles = exponentiated_hash_ints;

  std::vector<CryptoPP::Integer> req_shared_exponent = exponentiateInts(req_msg.hashed_exponentiated_eles, k, DL_P);
  resp_msg.req_hashed_exponentiated_eles = req_shared_exponent;

  network_driver->send(
    crypto_driver->encrypt_and_tag(
      AES_key, HMAC_key, &resp_msg
    )
  );
}