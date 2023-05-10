#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the nest bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the nest string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

// ================================================
// KEY EXCHANGE
// ================================================

/**
 * serialize DHPublicValue_Message.
 */
void DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize DHPublicValue_Message.
 */
int DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

// ================================================
// MESSAGES
// ================================================

/**
 * serialize UserToServer_Query_Message.
 */
void UserToServer_Query_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_Query_Message);

  // Add fields.
  put_string(chvec2str(relinkeys_to_chvec(this->rks)), data);

  // Add number of ciphertexts
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t query_size = this->query.size();
  std::memcpy(&data[idx], &query_size, sizeof(size_t));

  // Put the ciphertexts in.
  for (int i = 0; i < query_size; i++)
    put_string(chvec2str(ciphertext_to_chvec(this->query[i])), data);
}

/**
 * deserialize UserToServer_Query_Message.
 */
int UserToServer_Query_Message::deserialize(std::vector<unsigned char> &data,
                                            seal::SEALContext ctx) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_Query_Message);

  // Get fields.
  std::string rks_str;
  int n = 1;
  n += get_string(&rks_str, data, n);
  this->rks = chvec_to_relinkeys(ctx, str2chvec(rks_str));

  // Get number of ciphertexts.
  size_t query_size;
  std::memcpy(&query_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  // Get each ciphertext.
  for (int i = 0; i < query_size; i++) {
    std::string ciphertext_str;
    n += get_string(&ciphertext_str, data, n);
    this->query.push_back(chvec_to_ciphertext(ctx, str2chvec(ciphertext_str)));
  }
  return n;
}

/**
 * serialize UserToServer_Query_Message.
 */
void ServerToUser_Response_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_Response_Message);

  // Add fields.
  put_string(chvec2str(ciphertext_to_chvec(this->response)), data);
}

/**
 * deserialize UserToServer_Query_Message.
 */
int ServerToUser_Response_Message::deserialize(std::vector<unsigned char> &data,
                                               seal::SEALContext ctx) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_Response_Message);

  // Get fields.
  std::string response_str;
  int n = 1;
  n += get_string(&response_str, data, n);
  this->response = chvec_to_ciphertext(ctx, str2chvec(response_str));
  return n;
}
