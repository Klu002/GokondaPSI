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
  repl.add_action("get", "get <set>", &AgentClient::HandleRetrieve);
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
  input_split.erase(input_split.begin());
  std::set<std::string> query_set(input_split.begin(), input_split.end());
  // for (auto &e: query_set) {
  //   std::cout << e <<std::endl;
  // }

  // Call retrieve
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();
  this->DoRetrieve(network_driver, crypto_driver, query_set);
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
                        std::shared_ptr<CryptoDriver> crypto_driver, std::set<std::string> query) {
  // Initialize drivers.
  network_driver->connect(this->address, this->port);

  // Key exchange with server. From here on out, any outgoing messages should
  // be encrypted and MAC tagged. Incoming messages should be decrypted and have
  // their MAC checked.
  auto keys = this->HandleKeyExchange(crypto_driver, network_driver);

  // TODO: implement me!
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Setup: Generate private exponent k
  CryptoPP::AutoSeededRandomPool prg;
  CryptoPP::Integer k(prg, 0, DL_Q);

  // Round 1: Requester sends H(local_set_r)^k_r
  std::vector<CryptoPP::Integer> int_arr;
  for (auto const &str: query) {
    std::string hash_str = crypto_driver->hash(str);
    int_arr.push_back(CryptoPP::Integer(hash_str.c_str()));
  }

  std::vector<CryptoPP::Integer> exponentiated_hash_ints = exponentiateInts(int_arr, k, DL_P);
  std::random_shuffle(exponentiated_hash_ints.begin(), exponentiated_hash_ints.end());
  PSIRequest_Message req_msg;
  req_msg.hashed_exponentiated_eles = exponentiated_hash_ints;
  network_driver->send(
    crypto_driver->encrypt_and_tag(
      AES_key, HMAC_key, &req_msg
    )
  );

  // Round 2: Requester recieves H(local_set_r)^(k_r k_s) and H(local_set_s)^k_s
  PSIResponse_Message resp_msg;
  auto[serialized_resp, is_valid] = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
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
  // Fuck it, just do ca so we dont have to decrypt
  std::cout << intersection.size() << std::endl;

  return CryptoPP::Integer();
}