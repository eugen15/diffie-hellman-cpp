// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <format>
#include <vector>

#include "result.h"
#include "base-helpers.h"
#include "diffie-hellman.h"

#include "tester.h"

Tester::Tester(int primeLengthInBits, int generator)
: primeLengthInBits_(primeLengthInBits)
, generator_(generator) {
}

void Tester::Run() {
  using Impl = DiffieHellman::Implementation;

  std::vector<std::pair<Impl, Impl>> tests = {
    {Impl::OpenSSL, Impl::OpenSSL},
    {Impl::LibreSSLDH, Impl::LibreSSLDH},
    {Impl::LibreSSLDH, Impl::LibreSSLBN},
    {Impl::LibreSSLBN, Impl::LibreSSLDH},
    {Impl::OpenSSL, Impl::Boost},
    {Impl::Boost, Impl::OpenSSL},
    {Impl::LibreSSLDH, Impl::Boost},
    {Impl::Boost, Impl::LibreSSLDH},
  };

  for (const auto& test : tests) {
    auto alice = DiffieHellman::Create(test.first);
    auto bob = DiffieHellman::Create(test.second);
    if (alice && bob) {
      std::cout << "--------------------------------------------------------" << std::endl;

      std::string testDescription = std::format("ALICE {} <-> BOB {}",
        alice->GetImplementaionName(), bob->GetImplementaionName());
      std::cout << testDescription << std::endl;

      auto result = DoTest(alice.get(), bob.get());

      std::string resultDescription = (result) ? "success" : result.GetDescription();
      std::cout << "RESULT: " << resultDescription << std::endl << std::endl;
    }
  }
}

Result Tester::DoTest(DiffieHellman* alice, DiffieHellman* bob) {
  Result result;
  
  std::cout << "Generating the prime (may be slow)..." << std::endl;

  std::string hexPrime, hexGenerator;
  if (!(result = alice->GenerateParameters(primeLengthInBits_, generator_)) ||
      !(result = alice->GetParameters(&hexPrime, &hexGenerator))) {
    return result;
  }

  PrintObjectLength("ALICE prime length", alice->GetPrimeLength(), hexPrime);

  std::cout << "ALICE prime: " << hexPrime << std::endl;
  std::cout << "ALICE generator: " << hexGenerator << std::endl;

  std::string aliceHexPrivateKey, aliceHexPublicKey;
  if (!(result = alice->GenerateKeys()) ||
      !(result = alice->GetPrivateKey(&aliceHexPrivateKey)) ||
      !(result = alice->GetPublicKey(&aliceHexPublicKey))) {
    return result;
  }

  PrintObjectLength("ALICE private key length",
    alice->GetPrivateKeyLength(), aliceHexPrivateKey);

  std::cout << "ALICE private key: " << aliceHexPrivateKey << std::endl;

  PrintObjectLength("ALICE public key length",
    alice->GetPublicKeyLength(), aliceHexPublicKey);

  std::cout << "ALICE public key: " << aliceHexPublicKey << std::endl;

  std::string bobHexPrivateKey, bobHexPublicKey;
  if (!(result = bob->SetParameters(hexPrime, hexGenerator)) ||
    !(result = bob->GenerateKeys()) ||
    !(result = bob->GetPrivateKey(&bobHexPrivateKey)) ||
    !(result = bob->GetPublicKey(&bobHexPublicKey))) {
    return result;
  }

  PrintObjectLength("BOB private key length",
    bob->GetPrivateKeyLength(), bobHexPrivateKey);

  std::cout << "BOB private key: " << bobHexPrivateKey << std::endl;

  PrintObjectLength("BOB public key length",
    bob->GetPublicKeyLength(), bobHexPrivateKey);

  std::cout << "BOB public key: " << bobHexPublicKey << std::endl;

  std::string aliceHexSharedSecret;
  if (!(result = alice->DeriveSharedSecret(bobHexPublicKey, &aliceHexSharedSecret))) {
    return result;
  }

  std::cout << "ALICE shared secret length (hex digits): "
    << aliceHexSharedSecret.size() << std::endl;
  std::cout << "ALICE shared secret: " << aliceHexSharedSecret << std::endl;

  std::string bobHexSharedSecret;
  if (!(result = bob->DeriveSharedSecret(aliceHexPublicKey, &bobHexSharedSecret))) {
    return result;
  }

  std::cout << "BOB shared secret length (hex digits): "
    << bobHexSharedSecret.size() << std::endl;
  std::cout << "BOB shared secret: " << bobHexSharedSecret << std::endl;

  if (aliceHexSharedSecret != bobHexSharedSecret) {
    return {Result::Fail, "The shared secrets are different!"};
  }

  return {Result::Success};
}

void Tester::PrintObjectLength(std::string_view comment,
    std::tuple<int, int> bitsBytes, const std::string& hex) {
  std::string line = std::format("{} (bits/bytes/hex digits): {}/{}/{}",
    comment, std::get<0>(bitsBytes), std::get<1>(bitsBytes), hex.size());
  std::cout << line << std::endl;
}