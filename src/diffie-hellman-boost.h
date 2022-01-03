// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random/mersenne_twister.hpp>

#include "result.h"
#include "diffie-hellman.h"

// Diffie-Hellman implementation based on the C++ boost library.
class DiffieHellmanBoost : public DiffieHellman {
 public:
  DiffieHellmanBoost();
  ~DiffieHellmanBoost() override;

  std::string_view GetImplementaionName() const override;

  Result GenerateParameters(int primeLengthInBits, int generator) override;

  Result SetParameters(std::string_view hexPrime, std::string_view hexGenerator) override;
  Result GetParameters(std::string* hexPrime, std::string* hexGenerator) const override;

  Result GenerateKeys() override;
  Result GetPrivateKey(std::string* hexPrivateKey) const override;
  Result GetPublicKey(std::string* hexPublicKey) const override;

  Result DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const override;

  std::tuple<int, int> GetPrimeLength() const override;
  std::tuple<int, int> GetPrivateKeyLength() const override;
  std::tuple<int, int> GetPublicKeyLength() const override;

 private:
  using cpp_int = boost::multiprecision::cpp_int;  

  cpp_int prime_;
  cpp_int generator_;
  cpp_int privateKey_;
  cpp_int publicKey_;

};
