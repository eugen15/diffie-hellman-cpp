// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chrono>
#include <iostream>
#include <format>

#include <boost/exception/diagnostic_information.hpp>
#include <boost/exception_ptr.hpp>

#include <openssl/bn.h>

#include "base-helpers.h"
#include "diffie-hellman-boost.h"

using cpp_int = boost::multiprecision::cpp_int;

static std::string
ConverCPPIntToHex(const boost::multiprecision::cpp_int& num) {
  std::stringstream ss;
  ss << std::uppercase << std::hex << num;
  std::string hex = ss.str();
  // Add the top 0 if necessary
  if (hex.size() % 2) {
    hex = "0" + hex;
  }
  return hex;
}

static boost::multiprecision::cpp_int
ConveryHexToCPPInt(std::string_view hex) {
  return boost::multiprecision::cpp_int{std::string("0x") + std::string(hex)};
}

DiffieHellmanBoost::DiffieHellmanBoost() {
}

DiffieHellmanBoost::~DiffieHellmanBoost() {
}

std::string_view DiffieHellmanBoost::GetImplementationName() const {
  return "boost cpp_int DH";
}

Result DiffieHellmanBoost::GenerateParameters(int primeLengthInBits, int generator) {
  if (generator <= 1) {
    return Result{Result::Fail, "Bad generator value."};
  }

  try {
    unsigned int minMillerRabinChecks = GetMillerRabinMinChecks(primeLengthInBits);

    // We must use different generators for the tests and prime generation,
    // otherwise we get false positives.
    // https://www.boost.org/doc/libs/1_60_0/libs/multiprecision/doc/html/boost_multiprecision/tut/primetest.html
    boost::random::mt11213b primeGenerator(clock());
    boost::random::mt19937 testGenerator(clock());

    std::array<std::uint16_t, Primes.size()> mods{};

    while (true) {
      cpp_int prime = ProbableSafePrime(primeLengthInBits, generator, primeGenerator);
      if (miller_rabin_test(prime, minMillerRabinChecks, testGenerator)) {
        // The value is probably prime, see if (prime - 1) / 2 is also prime.
        if (miller_rabin_test((prime - 1) / 2, minMillerRabinChecks, testGenerator)) {
          prime_ = std::move(prime);
          generator_ = cpp_int{generator};
          break;
        }
      }
    }
  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return {Result::Success};
}

Result DiffieHellmanBoost::SetParameters(std::string_view hexPrime, std::string_view hexGenerator) {
  try {
    prime_ = ConveryHexToCPPInt(hexPrime);
    generator_ = ConveryHexToCPPInt(hexGenerator);

  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return Result{Result::Success};
}
Result DiffieHellmanBoost::GetParameters(std::string* hexPrime, std::string* hexGenerator) const {
  try {
    *hexPrime = ConverCPPIntToHex(prime_);
    *hexGenerator = ConverCPPIntToHex(generator_);

  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return Result{Result::Success};
}

Result DiffieHellmanBoost::GenerateKeys() {
  try {
    // It will return prime len - 1 anyway because we always set the top bit.
    // For example, 255 for a 256 bit prime.
    unsigned int len = boost::multiprecision::msb(prime_);

    // Configure the generator.
    cpp_int max = cpp_int{1} << len;
    boost::random::uniform_int_distribution<cpp_int> generatePrivateKey{0, max};
    boost::random::mt11213b privateKeyGenerator(clock());

    // Generate the private key.
    cpp_int privateKey = generatePrivateKey(privateKeyGenerator);

    // Derive the public key.
    cpp_int publicKey = boost::multiprecision::powm(generator_, privateKey, prime_);

    privateKey_ = std::move(privateKey);
    publicKey_ = std::move(publicKey);

  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return {Result::Success};
}

Result DiffieHellmanBoost::GetPrivateKey(std::string* hexPrivateKey) const {
  try {
    hexPrivateKey->clear();
    hexPrivateKey->append(ConverCPPIntToHex(privateKey_));
    if (hexPrivateKey->empty()) {
      return {Result::Fail, "The private key is empty."};
    }
  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return Result{Result::Success};
}

Result DiffieHellmanBoost::GetPublicKey(std::string* hexPublicKey) const {
  try {
    hexPublicKey->clear();
    hexPublicKey->append(ConverCPPIntToHex(publicKey_));
    if (hexPublicKey->empty()) {
      return {Result::Fail, "The public key is empty."};
    }
  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }

  return Result{Result::Success};
}

static Result CheckPublicKey(const boost::multiprecision::cpp_int& prime,
    const boost::multiprecision::cpp_int& publicKey) {
  try {
    if (publicKey <= 1) {
      return {Result::Fail, "The public key is too small."};
    }
    if (publicKey >= prime) {
      return {Result::Fail, "The public key is too large."};
    }

  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }
   
  return {Result::Success};
}

Result DiffieHellmanBoost::DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const {
  try {
    cpp_int peerPublicKey = ConveryHexToCPPInt(hexPeerPublicKey);

    if (Result result = CheckPublicKey(prime_, peerPublicKey); !result) {
      return result;
    }

    cpp_int sharedSecret = boost::multiprecision::powm(peerPublicKey, privateKey_, prime_);
    *hexSharedSecret = ConverCPPIntToHex(sharedSecret);

  } catch (const boost::exception& e) {
    return {Result::Fail, boost::diagnostic_information(e)};
  }
  return {Result::Success};
}

std::tuple<int, int> DiffieHellmanBoost::GetPrimeLength() const {
  try {
    // bytes = (bits - 1) / 8 + 1
    return {boost::multiprecision::msb(prime_) + 1,
      boost::multiprecision::msb(prime_) / 8 + 1};
  } catch (...) {
  }

  return {-1, -1};
}

std::tuple<int, int> DiffieHellmanBoost::GetPrivateKeyLength() const {
  try {
    return {boost::multiprecision::msb(privateKey_) + 1,
      boost::multiprecision::msb(privateKey_) / 8 + 1};
  } catch (...) {
  }

  return {-1, -1};
}

std::tuple<int, int> DiffieHellmanBoost::GetPublicKeyLength() const {
  try {
    return {boost::multiprecision::msb(publicKey_) + 1,
      boost::multiprecision::msb(publicKey_) / 8 + 1};
  } catch (...) {
  }

  return {-1, -1};
}

unsigned int DiffieHellmanBoost::GetMillerRabinMinChecks(int primeLengthInBits) {
  if (primeLengthInBits > 2048) {
    return 128;
  }
  return 64;
}

int DiffieHellmanBoost::GetTrivialDivisionNum(int primeLengthInBits) {
  if (primeLengthInBits <= 512) {
    return 64;
  } else if (primeLengthInBits <= 1024) {
    return 128;
  } else if (primeLengthInBits <= 2048) {
    return 384;
  } else if (primeLengthInBits <= 4096) {
    return 1024;
  }
  return Primes.size();
}

std::tuple<cpp_int, cpp_int> DiffieHellmanBoost::GetAddRem(int generator) {
  // See dh_builtin_genparams
  // libressl: crypto\dh\dh_gen.c 
  boost::multiprecision::cpp_int add, rem;
  switch (generator) {
  case 2:
    add = 24;
    rem = 11;
    break;
  case 5:
    add = 10;
    rem = 3;
    break;
  default:
    add = 2;
    rem = 1;
  }
  return {add, rem};
}

cpp_int DiffieHellmanBoost::ProbableSafePrime(int primeLengthInBits,
    int generator, boost::random::mt11213b& primeGenerator) {
  int trivialDivisionNum = GetTrivialDivisionNum(primeLengthInBits);
  std::uint64_t maxDelta = 0xFFFFFFFFFFFFFFFFULL - Primes[trivialDivisionNum - 1];

  // Prepare cpp_int add/rem for the generator.
  auto [add, rem] = GetAddRem(generator);

  // Prepare the top bit.
  cpp_int topBit = cpp_int{0x80} << (primeLengthInBits - 8);

  // Prepare the bottom bit.
  cpp_int bottomBit{1};

  // Generation limits.
  cpp_int max = cpp_int{1} << primeLengthInBits;
  boost::random::uniform_int_distribution<cpp_int> generatePrime{0, max};

  cpp_int rnd;
  while (true) {
    rnd = generatePrime(primeGenerator);

    // Add top/bottom.
    rnd = rnd | topBit | bottomBit;

    // The prime should fulfill the condition prime % add == rem
    // in order to suit a given generator.
    cpp_int mod = rnd % add;
    rnd = rnd - mod + rem;

    // Probably the second condition is overhead?
    if (boost::multiprecision::msb(rnd) + 1 < primeLengthInBits || rnd < 5) {
      rnd += add;
    }

    auto [success, delta] = IncreaseProbabilityOfBeingPrime(primeLengthInBits, rnd, add);
    if (success) {
      rnd += delta;
      break;
    }
  }

  return rnd;
}

std::tuple<bool, std::uint64_t>
DiffieHellmanBoost::IncreaseProbabilityOfBeingPrime(int primeLengthInBits,
    cpp_int rnd, cpp_int add) {  
  int trivialDivisionNum = GetTrivialDivisionNum(primeLengthInBits);

  std::uint64_t maxDelta = 0xFFFFFFFFFFFFFFFFULL - Primes[trivialDivisionNum - 1];
  std::uint64_t rnd64bit = rnd.convert_to<std::uint64_t>();
  std::uint64_t add64bit = add.convert_to<std::uint64_t>();
  std::uint64_t delta = 0;

  auto mods = std::make_unique<std::uint16_t[]>(Primes.size());

  for (int i = 1; i < trivialDivisionNum; ++i) {
    cpp_int mod = rnd % Primes[i];
    mods[i] = mod.convert_to<std::uint16_t>();
  }  

  bool continueTesting = true;
  while (continueTesting) {
    continueTesting = false;
    for (int i = 1; i < trivialDivisionNum; ++i) {
      // Check if it is a prime.
      if (primeLengthInBits <= 31 && delta <= 0x7FFFFFFF) {
        std::uint64_t sq = static_cast<std::uint64_t>(Primes[i]) *
          static_cast<std::uint64_t>(Primes[i]);
        if (sq > rnd64bit + delta) {
          return {true, delta};
        }
      }
      // prime mod p == 1 implies q = (prime - 1) / 2 is divisible by p.
      if ((mods[i] + delta) % Primes[i] <= 1) {
        delta += add64bit;
        if (delta > maxDelta) {
          return {false, 0};
        }
        continueTesting = true;
        break;
      }
    }
  }

  return {true, delta};
}