#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "seal/seal.h"

#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/misc.h>
#include <crypto++/sha.h>
#include <crypto++/nbtheory.h>

// String <=> Vec<char>.
std::string chvec2str(std::vector<unsigned char> data);
std::vector<unsigned char> str2chvec(std::string s);

// String <=> Hex.
std::string hex_encode(std::string s);
std::string hex_decode(std::string s);

// SecByteBlock <=> Integer.
CryptoPP::Integer byteblock_to_integer(CryptoPP::SecByteBlock block);
CryptoPP::SecByteBlock integer_to_byteblock(CryptoPP::Integer x);

// SecByteBlock <=> string.
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s);

// Printers.
void print_string_as_hex(std::string str);
void print_key_as_int(CryptoPP::SecByteBlock block);
void print_key_as_hex(CryptoPP::SecByteBlock block);

// Splitter.
std::vector<std::string> string_split(std::string str, char delimiter);

// BGV conversions
std::vector<unsigned char> params_to_chvec(seal::EncryptionParameters params);
seal::EncryptionParameters chvec_to_params(std::vector<unsigned char> data);
std::vector<unsigned char> pubkey_to_chvec(seal::PublicKey pk);
seal::PublicKey chvec_to_pubkey(seal::SEALContext ctx,
                                std::vector<unsigned char> data);
std::vector<unsigned char> ciphertext_to_chvec(seal::Ciphertext ct);
seal::Ciphertext chvec_to_ciphertext(seal::SEALContext ctx,
                                     std::vector<unsigned char> data);
std::vector<unsigned char> relinkeys_to_chvec(seal::RelinKeys rk);
seal::RelinKeys chvec_to_relinkeys(seal::SEALContext ctx,
                                   std::vector<unsigned char> data);

std::vector<CryptoPP::Integer> exponentiateInts(
  std::vector<CryptoPP::Integer> ints,
  CryptoPP::Integer exponent,
  CryptoPP::Integer mod);