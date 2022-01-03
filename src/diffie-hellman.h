// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <openssl/bn.h>

#include "libressl-helpers.h"

#include "result.h"

// The Diffie-Hellman interface.
class DiffieHellman {
 public:

  enum class Implementation {
    Undefined = 0,
    LibreSSLDH,   // Based on libressl DH
    LibreSSLBN,   // Based on libressl BIGNUM
    Boost         // Based on boost
  };

  // Create an instance.
  static std::unique_ptr<DiffieHellman> Create(Implementation impl);

  // Default constructor.
  DiffieHellman() = default;

  // For derived classes.
  virtual ~DiffieHellman() {}

  // Gets implementation name.
  virtual std::string_view GetImplementaionName() const = 0;

  // Generates a safe prime with the specified length and
  // sets the generator.
  virtual Result GenerateParameters(int primeLengthInBits, int generator) = 0;

  // Sets the prime and the generator.
  // They must be specified in hex format.
  virtual Result SetParameters(std::string_view hexPrime, std::string_view hexGenerator) = 0;

  // Gets the prime and the generator.
  virtual Result GetParameters(std::string* hexPrime, std::string* hexGenerator) const = 0;

  // Generate a private key and then derives a public key.
  virtual Result GenerateKeys() = 0;

  // Gets the private key.
  virtual Result GetPrivateKey(std::string* hexPrivateKey) const = 0;

  // Gets the public key.
  virtual Result GetPublicKey(std::string* hexPublicKey) const = 0;

  // Derives the shared secret based on this objects values and the peer public key.
  virtual Result DeriveSharedSecret(std::string_view hexPeerPublicKey, std::string* hexSharedSecret) const = 0;

  // Gets the lengths in bits and in bytes (for debug).
  // Returns {-1, -1} if anything fails.
  virtual std::tuple<int, int> GetPrimeLength() const = 0;
  virtual std::tuple<int, int> GetPrivateKeyLength() const = 0;
  virtual std::tuple<int, int> GetPublicKeyLength() const = 0;

private:
  // Non-copyable.
  DiffieHellman(const DiffieHellman&) = delete;
  DiffieHellman& operator=(const DiffieHellman&) = delete;
};
