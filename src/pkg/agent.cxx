#include "../../include/pkg/agent.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"

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
AgentClient::AgentClient(std::string address, int port, int d, int s) {
  this->address = address;
  this->port = port;
  this->dimension = d;
  this->sidelength = s;

  this->hypercube_driver = std::make_shared<HypercubeDriver>(
      d, s, CryptoPP::Integer(PLAINTEXT_MODULUS));
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();
  initLogger();
}

/**
 * run
 */
void AgentClient::run() {
  REPLDriver<AgentClient> repl = REPLDriver<AgentClient>(this);
  repl.add_action("get", "get <key>", &AgentClient::HandleRetrieve);
  repl.run();
}

/**
 * Come to a shared secret
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
AgentClient::HandleKeyExchange(std::shared_ptr<CryptoDriver> crypto_driver,
                               std::shared_ptr<NetworkDriver> network_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Respond with m = (g^b, g^a) signed with our private DSA key
  DHPublicValue_Message public_value_s;
  public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> public_value_data;
  public_value_s.serialize(public_value_data);
  network_driver->send(public_value_data);

  // Listen for g^a
  std::vector<unsigned char> server_public_value = network_driver->read();
  DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value);

  // Recover g^ab
  auto dh_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.public_value);

  // Generate keys
  auto AES_key = crypto_driver->AES_generate_key(dh_shared_key);
  auto HMAC_key = crypto_driver->HMAC_generate_key(dh_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  return keys;
}

/**
 * Privately retrieve a value from the cloud.
 */
void AgentClient::HandleRetrieve(std::string input) {
  // Parse input.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 2) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  int key = std::stoi(input_split[1]);

  // Call retrieve
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();
  this->DoRetrieve(network_driver, crypto_driver, key);
}

/**
 * Privately retrieve a value from the cloud. This function should:
 * 0) Connect and handle key exchange.
 * 1) Generate parameters, context, and keys. See constants.hpp.
 * 2) Generate a selection vector based on the key's coordinates.
 * 3) Send the selection vector to the server and decode the response.
 */
CryptoPP::Integer
AgentClient::DoRetrieve(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver, int query) {
  // Initialize drivers.
  network_driver->connect(this->address, this->port);

  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(crypto_driver, network_driver);

  // TODO: implement me!
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Initializing stuff
  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
  parms.set_plain_modulus(PLAINTEXT_MODULUS);
  seal::SEALContext context(parms);
  seal::KeyGenerator keygen(context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);
  seal::RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  seal::Encryptor encryptor(context, public_key);
  seal::Decryptor decryptor(context, secret_key);

  // Generating selection vector
  std::vector<int> coords = this->hypercube_driver->to_coords(query);
  std::vector<std::vector<seal::Ciphertext>> choice_matrix(this->dimension, std::vector<seal::Ciphertext>());

  for (int d = 0; d < this->dimension; d++) {
    for (int sideIdx = 0; sideIdx < this->sidelength; sideIdx++) {
      seal::Ciphertext encrypted;
      seal::Plaintext choice_plain(CryptoPP::IntToString(CryptoPP::Integer(int(sideIdx == coords[d])), 16));
      encryptor.encrypt(choice_plain, encrypted);
      choice_matrix[d].push_back(encrypted);
    }
  }

  std::vector<seal::Ciphertext> choice_vector;
  for (auto& innerVec: choice_matrix) {
    choice_vector.insert(choice_vector.end(), innerVec.begin(), innerVec.end());
  }

  std::cout << "Converted choice matrix to choice vector" << std::endl;

  // Sending selection vector to the server
  UserToServer_Query_Message qMsg;
  qMsg.rks = relin_keys;
  qMsg.query = choice_vector;
  network_driver->send(
    crypto_driver->encrypt_and_tag(
      AES_key, HMAC_key, &qMsg
    )
  );

  // Retrieving server response
  ServerToUser_Response_Message respMsg;
  auto [serialized_respMsg, isValid] = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!isValid) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid response from server");
  }
  respMsg.deserialize(serialized_respMsg, context);

  // Decoding server response
  seal::Plaintext decrypted;
  decryptor.decrypt(respMsg.response, decrypted);
  CryptoPP::Integer I(("0x" + decrypted.to_string()).c_str());

  std::cout << I << std::endl;
  return I;
}