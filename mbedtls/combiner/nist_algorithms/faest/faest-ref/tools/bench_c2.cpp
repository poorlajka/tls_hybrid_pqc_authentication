/*
 *  SPDX-License-Identifier: MIT
 */

#include <array>

extern "C" {
#include "api.h"
}

#include <catch_amalgamated.hpp>

TEST_CASE("bench keygen", "[.][bench]") {
  std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
  std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;

  BENCHMARK("keygen") {
    return FAEST_crypto_sign_keypair(pk.data(), sk.data());
  };
}

TEST_CASE("bench sign", "[.][bench]") {
  std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
  std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;
  FAEST_crypto_sign_keypair(pk.data(), sk.data());
  const std::string message =
      "This document describes and specifies the FAEST digital signature algorithm.";
  std::vector<unsigned char> signed_message(CRYPTO_BYTES + message.size());
  unsigned long long signed_message_len = CRYPTO_BYTES + message.size();

  BENCHMARK("sign") {
    return FAEST_crypto_sign(signed_message.data(), &signed_message_len,
                       reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                       sk.data());
  };

#if !defined(NDEBUG)
  REQUIRE(signed_message_len == signed_message.size());
#endif
}

TEST_CASE("bench verify", "[.][bench]") {
  std::array<unsigned char, CRYPTO_SECRETKEYBYTES> sk;
  std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> pk;
  FAEST_crypto_sign_keypair(pk.data(), sk.data());
  const std::string message =
      "This document describes and specifies the FAEST digital signature algorithm.";
  std::vector<unsigned char> signed_message(CRYPTO_BYTES + message.size());
  unsigned long long signed_message_len = CRYPTO_BYTES + message.size();
  FAEST_crypto_sign(signed_message.data(), &signed_message_len,
              reinterpret_cast<const unsigned char*>(message.data()), message.size(), sk.data());
  std::vector<unsigned char> opened_message(message.size());
  unsigned long long opened_message_len = message.size();

  BENCHMARK("verify") {
    return FAEST_crypto_sign_open(opened_message.data(), &opened_message_len, signed_message.data(),
                            signed_message_len, pk.data());
  };

#if !defined(NDEBUG)
  REQUIRE(opened_message_len == opened_message.size());
  REQUIRE(opened_message ==
          std::vector<unsigned char>(reinterpret_cast<const unsigned char*>(message.c_str()),
                                     reinterpret_cast<const unsigned char*>(message.c_str()) +
                                         message.size()));
#endif
}
