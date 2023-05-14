#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

//#include "seal/seal.h"

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dsa.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 1,
  DHPublicValue_Message = 2,
  PSIRequest_Message = 3,
  PSIResponse_Message = 4,
  UserToServer_Query_Message = 5,
  ServerToUser_Response_Message = 6,
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// struct SerializableWithContext {
//   virtual void serialize(std::vector<unsigned char> &data) = 0;
//   virtual int deserialize(std::vector<unsigned char> &data,
//                           seal::SEALContext ctx) = 0;
// };

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KEY EXCHANGE
// ================================================

struct DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// PSI Basic
// ================================================

struct PSIRequest_Message : public Serializable {
  std::vector<CryptoPP::Integer> hashed_exponentiated_eles;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct PSIResponse_Message : public Serializable {
  std::vector<CryptoPP::Integer> req_hashed_exponentiated_eles;
  std::vector<CryptoPP::Integer> resp_hashed_exponentiated_eles;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};


// ================================================
// MESSAGES
// ================================================

// struct UserToServer_Query_Message : public SerializableWithContext {
//   seal::RelinKeys rks;
//   std::vector<seal::Ciphertext> query;

//   void serialize(std::vector<unsigned char> &data);
//   int deserialize(std::vector<unsigned char> &data, seal::SEALContext ctx);
// };

// struct ServerToUser_Response_Message : public SerializableWithContext {
//   seal::Ciphertext response;

//   void serialize(std::vector<unsigned char> &data);
//   int deserialize(std::vector<unsigned char> &data, seal::SEALContext ctx);
// };
