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
  repl.add_action("insert", "insert <key> <value>", &CloudClient::HandleInsert);
  repl.add_action("get", "get <key>", &CloudClient::HandleGet);
  repl.run();
}

/**
 * Insert a value into the database
 */
void CloudClient::HandleInsert(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);
  CryptoPP::Integer value = CryptoPP::Integer(std::stoi(input_split[2]));
  this->hypercube_driver->insert(key, value);
  this->cli_driver->print_success("Inserted value!");
}

/**
 * Get a value from the database
 */
void CloudClient::HandleGet(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);
  CryptoPP::Integer value = this->hypercube_driver->get(key);
  this->cli_driver->print_success("Get value: " + CryptoPP::IntToString(value));
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

  // Initializing parameters and context
  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus(PLAINTEXT_MODULUS);
  seal::SEALContext context(parms);
  seal::Evaluator evaluator(context);

  // Recieving the selection vector
  UserToServer_Query_Message qMsg;
  auto [serialized_qMsg, isValid] = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!isValid) {
    network_driver->disconnect();
    throw std::runtime_error("Recieved invalid query message from client");
  }
  qMsg.deserialize(serialized_qMsg, context);

  // Reconstruct selection hypercube
  std::cout << "reconstructing hypercube" << std::endl;
  std::vector<std::vector<seal::Ciphertext>> selection_hypercube(this->dimension, std::vector<seal::Ciphertext>());
  for (int d = 0; d < this->dimension; d++) {
    for (int sideIdx = 0; sideIdx < this->sidelength; sideIdx++) {
      selection_hypercube[d].push_back(qMsg.query[d * this->sidelength + sideIdx]);
    }
  }

  // Evaluate query
  std::cout << "evaluating query" << std::endl;
  int n = std::pow(this->sidelength, this->dimension);
  std::vector<seal::Ciphertext> cts;

  for (int entryIdx = 0; entryIdx < n; entryIdx++) {
    std::vector<int> coords = this->hypercube_driver->to_coords(entryIdx);
    seal::Ciphertext ctProduct = selection_hypercube[0][coords[0]];
    // Start at second dimension because we initialized the product to the first dimension ciphertext
    for (int d = 1; d < this->dimension; d++) {
      evaluator.multiply_inplace(ctProduct, selection_hypercube[d][coords[d]]);
      evaluator.relinearize_inplace(ctProduct, qMsg.rks);
    }
    
    CryptoPP::Integer entryInt = this->hypercube_driver->get(entryIdx);
    seal::Plaintext entry(CryptoPP::IntToString(entryInt, 16));
    evaluator.multiply_plain_inplace(ctProduct, entry);
    cts.push_back(ctProduct);
  }

  seal::Ciphertext ct;
  evaluator.add_many(cts, ct);

  // Sending result back to client
  ServerToUser_Response_Message respMsg;
  respMsg.response = ct;
  network_driver->send(
    crypto_driver->encrypt_and_tag(
      AES_key, HMAC_key, &respMsg
    )
  );
}
